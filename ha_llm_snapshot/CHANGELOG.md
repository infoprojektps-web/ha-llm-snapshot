# Changelog

## 0.2.0

- Add `HEALTH_REPORT.md` and `health-report.json` with prioritized integration,
  device, entity, automation, repair, and update findings.
- Detect clusters of unavailable entities and identify automations that depend
  on them.
- Detect duplicate automation IDs and whole automations repeated with YAML
  anchors and aliases.
- Collect repairs on every diagnostic export and conditionally collect system
  logs plus targeted integration/device diagnostics when an issue is detected.
- Keep diagnostic collection best-effort: unavailable endpoints are recorded in
  the snapshot and never prevent the ZIP from being created.
- Bound noisy diagnostic collections and apply the mandatory credential filter.

## 0.1.1

- Preserve complete Home Assistant entity IDs, including long tracker IDs.
- Preserve technical identifiers such as local IP addresses, MAC addresses,
  VINs, serial numbers, device registry identifiers, and connections.
- Keep credential filtering mandatory for passwords, tokens, API keys,
  authorization data, cookies, webhooks, and private keys.
- Make location redaction optional and disabled by default for full technical
  analysis.
- Improve recognition of secret-bearing keys that contain spaces.

## 0.1.0

- Initial experimental release.
- Complete entity inventory from registry and runtime states.
- Device, area, floor, label, integration, and service exports.
- Sanitized YAML configuration export.
- Dependency index and basic diagnostics.
- Ingress panel for snapshot generation and ZIP download.
