# Lynx

AI security testing that proves what it finds and opens the fix.

Lynx runs a full baseline scan of your app, then reviews every pull request for what
it introduces. Findings are proven by the harness, not claimed by a model, and fixes
are verified before a change request is opened.

> **Status:** pre-alpha. This repository currently defines the project structure;
> nothing scans yet.

## Develop

Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run lynx --version
uv run pytest --cov
```

Scan a folder:

```bash
uv run lynx scan path/to/repo --sarif lynx.sarif
```

`lynx scan` runs [gitleaks](https://github.com/gitleaks/gitleaks) (8.30) and
[OSV-Scanner](https://github.com/google/osv-scanner) (2.7) when they're on your `PATH`.
A missing detector is reported as "not run" in the summary and in the SARIF, never
as a clean result. OSV-Scanner looks dependencies up in the public OSV database, so
it needs network access.

See [AGENTS.md](AGENTS.md) for the layout, checks and contribution rules.

## License

GPL-3.0. See [LICENSE](LICENSE).
