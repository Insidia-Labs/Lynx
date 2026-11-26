# Lynx

AI security testing that proves what it finds and opens the fix.

Lynx runs a full baseline scan of your app, then reviews every pull request for what
it introduces. Findings are proven by the harness, not claimed by a model, and fixes
are verified before a change request is opened.

> **Status:** pre-alpha. `lynx scan` finds leaked secrets and vulnerable
> dependencies; source analysis, the agent and proofs come next.

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

Each scan has a run id, printed when it starts. If a scan is stopped (Ctrl-C, or a CI
job's SIGTERM), finish it with:

```bash
uv run lynx scan --resume <run id>
```

Detectors that already finished aren't run again.

See [AGENTS.md](AGENTS.md) for the layout, checks and contribution rules.

## License

GPL-3.0. See [LICENSE](LICENSE).
