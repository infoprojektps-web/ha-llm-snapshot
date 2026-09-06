"""Small ingress-only web panel for HA LLM Snapshot Exporter."""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Any

from aiohttp import web

from snapshot import SnapshotBuilder, load_options


APP_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = Path("/share/ha-llm-snapshots")
ARCHIVE_NAME = re.compile(r"^ha-llm-snapshot-\d{8}T\d{6}Z\.zip$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
LOGGER = logging.getLogger("ha_llm_snapshot")
INGRESS_PROXY_ADDRESS = "172.30.32.2"


class SnapshotService:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.last_result: dict[str, Any] | None = None
        self.last_error: str | None = None

    def archives(self) -> list[Path]:
        if not OUTPUT_DIR.is_dir():
            return []
        return sorted(
            (
                path
                for path in OUTPUT_DIR.glob("ha-llm-snapshot-*.zip")
                if path.is_file() and ARCHIVE_NAME.fullmatch(path.name)
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

    def status(self) -> dict[str, Any]:
        archives = self.archives()
        latest = archives[0] if archives else None
        result: dict[str, Any] = {
            "generating": self.lock.locked(),
            "latest": (
                {
                    "filename": latest.name,
                    "bytes": latest.stat().st_size,
                    "download_url": f"api/download/{latest.name}",
                }
                if latest
                else None
            ),
            "archive_count": len(archives),
        }
        if self.last_result:
            result["last_result"] = self.last_result
        if self.last_error:
            result["last_error"] = self.last_error
        return result

    async def generate(self) -> dict[str, Any]:
        if self.lock.locked():
            raise web.HTTPConflict(text="Snapshot jest już tworzony")
        async with self.lock:
            self.last_error = None
            try:
                options = load_options()
                result = await SnapshotBuilder(options).build()
                self.last_result = result
                LOGGER.info(
                    "Created %s (%s entities, %s bytes)",
                    result["filename"],
                    result["counts"]["entities"],
                    result["bytes"],
                )
                return result
            except Exception as exc:
                LOGGER.exception("Snapshot creation failed")
                self.last_error = str(exc)
                raise


SERVICE = SnapshotService()


@web.middleware
async def ingress_only(
    request: web.Request, handler: Any
) -> web.StreamResponse:
    """Accept traffic only from the authenticated Home Assistant ingress proxy."""
    if request.remote != INGRESS_PROXY_ADDRESS:
        raise web.HTTPForbidden(text="Ingress access only")
    return await handler(request)


async def index(_request: web.Request) -> web.FileResponse:
    return web.FileResponse(APP_DIR / "index.html")


async def health(_request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def status(_request: web.Request) -> web.Response:
    return web.json_response(SERVICE.status())


async def generate(_request: web.Request) -> web.Response:
    try:
        result = await SERVICE.generate()
    except web.HTTPException:
        raise
    except Exception:
        return web.json_response(
            {
                "success": False,
                "error": "Nie udało się utworzyć snapshotu. Sprawdź dziennik dodatku.",
            },
            status=500,
        )
    return web.json_response(result)


def resolve_archive(filename: str) -> Path:
    if not ARCHIVE_NAME.fullmatch(filename):
        raise web.HTTPNotFound()
    path = OUTPUT_DIR / filename
    if not path.is_file():
        raise web.HTTPNotFound()
    return path


async def download(request: web.Request) -> web.FileResponse:
    path = resolve_archive(request.match_info["filename"])
    return web.FileResponse(
        path,
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


async def download_latest(_request: web.Request) -> web.FileResponse:
    archives = SERVICE.archives()
    if not archives:
        raise web.HTTPNotFound(text="Nie ma jeszcze żadnego snapshotu")
    path = archives[0]
    return web.FileResponse(
        path,
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


def create_app() -> web.Application:
    app = web.Application(client_max_size=1024, middlewares=[ingress_only])
    app.router.add_get("/", index)
    app.router.add_get("/health", health)
    app.router.add_get("/api/status", status)
    app.router.add_post("/api/generate", generate)
    app.router.add_get("/api/download/latest", download_latest)
    app.router.add_get("/api/download/{filename}", download)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8099, access_log=None)
