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

See [AGENTS.md](AGENTS.md) for the layout, checks and contribution rules.

## License

GPL-3.0. See [LICENSE](LICENSE).
