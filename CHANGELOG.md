# Changelog

All notable changes to Lynx are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Findings schema (`lynx.core.findings`): immutable findings with a lifecycle
  (candidate, corroborated, proven, refuted), source or live locations, data-flow
  traces and proof needles.
- SARIF 2.1.0 writer (`lynx.core.sarif`) with CWE tags on rules and results; only
  proven and corroborated findings are reported.
- Configuration (`lynx.config`): `LYNX_TOOL_NAME`, `LYNX_INFORMATION_URI` and
  `LYNX_REPORTED_STATES`, read from environment variables only (never from a
  `.env` file), documented in `.env.example`.
- Secret masking (`lynx.core.mask`), applied to the SARIF report: known token formats
  (cloud, Git hosting, chat and AI provider keys, JWTs, private keys),
  `Authorization` values, password and key assignments, and credentials or secret
  query values in URLs.
- `lynx scan <path> [--sarif FILE]`: runs gitleaks (secrets) and OSV-Scanner
  (vulnerable dependencies) and writes one SARIF report. Exit code 0 when the scan
  finished, 2 when no detector could run; a missing or failed detector marks the
  report incomplete with the reason.
- Detectors run through `lynx.core.process`: no shell, no stdin, only an allow-list
  of environment variables, and killed with their children after
  `LYNX_DETECTOR_TIMEOUT` seconds.
- A source location can omit lines to mean the whole file (dependency findings).

## [0.0.1] - unreleased

### Added

- Project structure: package layout, dependencies locked with uv, CI, and the
  `lynx --version` command.
