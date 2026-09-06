# HA LLM Snapshot Exporter

A Home Assistant add-on that creates a portable snapshot of your Home Assistant installation for analysis by ChatGPT, Codex, Claude, Gemini, or another external LLM.

The snapshot contains the complete entity inventory, current states, devices, integrations, services, YAML configuration, dependency references, and an automatically generated health report.

## Features

- complete entity inventory, including disabled and temporarily unavailable entities;
- current entity states and attributes;
- devices, areas, floors, labels, integrations, and services;
- automations, scripts, scenes, packages, blueprints, and YAML dashboards;
- references between entities, services, and configuration files;
- detection of missing entity references;
- detection of duplicate automation IDs and repeated YAML automation blocks;
- health report with integration and device availability problems;
- identification of automations that depend on unavailable entities;
- optional collection of repairs, system logs, and targeted diagnostics when a problem is detected;
- SHA-256 manifest for exported files;
- web panel for one-click snapshot creation and ZIP download.

## Installation

1. Open Home Assistant.
2. Go to **Settings → Add-ons → Add-on Store**.
3. Open the three-dot menu in the upper-right corner.
4. Select **Repositories**.
5. Add this repository URL:

```text
https://github.com/infoprojektps-web/ha-llm-snapshot
```

6. Install **HA LLM Snapshot Exporter**.
7. Start the add-on and enable **Show in sidebar**.
8. Open the **LLM Snapshot** panel.

## Usage

Open the add-on panel and select **Create snapshot**.

After processing finishes, download the generated ZIP file and upload it to the LLM you want to use for analysis.

The recommended analysis order is:

1. `HEALTH_REPORT.md`
2. `health-report.json`
3. `snapshot-info.json`
4. `diagnostics.json`
5. `additional-diagnostics.json`
6. `entities_all.jsonl`
7. `references.json`
8. YAML files under `config/`

## Snapshot contents

The generated archive normally includes:

- `HEALTH_REPORT.md` — human-readable prioritized findings;
- `health-report.json` — structured health information;
- `additional-diagnostics.json` — filtered repairs, logs, and targeted diagnostics;
- `entities_all.jsonl` — complete entity inventory;
- `states.jsonl` — current entity states;
- `devices.json`, `areas.json`, `floors.json`, and `labels.json`;
- `integrations.json` and `services.json`;
- `references.json` — configuration dependencies;
- `diagnostics.json` and `snapshot-info.json`;
- sanitized Home Assistant YAML files;
- `manifest.json` with file hashes.

## Privacy and security

The add-on never copies:

- `secrets.yaml`;
- the `.storage` directory;
- authentication databases;
- Home Assistant databases;
- backups or media files.

Passwords, tokens, API keys, cookies, webhook identifiers, authorization headers, and URL credentials are automatically filtered.

Technical identifiers such as entity IDs, device IDs, IP addresses, MAC addresses, VINs, and serial numbers are intentionally preserved because they are required to analyze relationships between devices and automations.

Location redaction is optional and can be enabled in the add-on configuration.

Always review the generated ZIP before uploading it to an external service. User-created names, aliases, descriptions, and log messages may contain personal information.

## Diagnostic collection

The add-on always collects the basic Home Assistant inventory.

If it detects an unavailable entity or an integration in an error state, it attempts to collect additional information for the most relevant devices and integrations. This may include:

- Home Assistant repair issues;
- a limited number of system log entries;
- integration diagnostics;
- device diagnostics.

Diagnostic collection is best-effort. If a Home Assistant version or integration does not provide a diagnostic endpoint, the error is recorded in the snapshot and ZIP creation continues.

## Configuration

Available options include:

- include or exclude current states;
- include or exclude services;
- include packages and YAML dashboards;
- enable or disable extended diagnostics;
- redact locations;
- choose how many snapshots to retain.

The Home Assistant configuration is mounted read-only. The add-on writes only generated archives to `/share/ha-llm-snapshots/`.

## License

MIT License.
