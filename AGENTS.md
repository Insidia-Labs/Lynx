# Lynx — agent and contributor instructions

Lynx is an AI security testing harness by Insidia Labs. It runs a full baseline scan,
then reviews every pull request, proves what it finds with harness-run checks, and
opens verified fixes. It is Python 3.14, built on LangGraph, and licensed GPL-3.0.

## Layout

```
src/lynx/
  cli.py        the `lynx` command
  config.py     format constants and `LYNX_*` settings (see .env.example)
  core/         scope, masking, sandboxed subprocesses, findings schema, run store, reports
  engine/       the LangGraph run graph; nodes/ has one module per stage
  agent/        the investigate subgraph, tool rails, chat models; tools/ has the core tools
  codegraph/    wrapper over Taylon's code-graph index
  detectors/    Detector interface and adapters
  proof/        proof gate; provers/ runs mature tools with fixed settings
  fixer/        fix agent and verifier; emit/ opens change requests
  sandbox/      run containers and the egress proxy
  ai/           AI agent and LLM-app testing
  baseline/     baselines, backlog, fingerprints, new-vs-existing comparison
  agents/       custom agent.yaml schema and builder
  memory/       MEMORY.md notes
  mcp/          MCP server
  skills/       first-party SKILL.md folders
tests/          unit and integration tests
docs/design/    one page per design decision
```

## Evaluation

Lynx has no benchmark code of its own. It's measured by the Insidia Labs Test Suite
(`Insidia-Labs-Test-Suite`, a separate MIT-licensed repo), and its adapter lives
there. For the suite to score a run, `lynx scan` must:

- write SARIF 2.1.0, with CWE ids in `properties.tags` (for example `"CWE-89"`)
- report source findings by path relative to the scanned folder, with
  `region.startLine`, and live findings by their full URL
- exit 0 whenever the run finished, whatever it found, and non-zero only when it
  didn't finish
- print its exact version with `lynx --version`
- report its token and dollar cost, so the adapter can write `cost.json`

## Commands

```bash
uv sync                      # install dependencies (locked in uv.lock)
uv run ruff check .          # lint
uv run ruff format .         # format
uv run mypy                  # type check (strict)
uv run pytest --cov          # tests, with the 80% coverage floor
```

Run all four checks before committing.

## Versioning

- **Semantic Versioning.** Lynx stays on `0.x` until the first stable release; before
  1.0, a breaking change bumps the minor number (0.2.0 → 0.3.0).
- **One source of truth:** `version` in `pyproject.toml`. `lynx.__version__` reads it
  from the installed package, so never type the version anywhere else.
- **Bumping:** `uv version --bump patch` (or `minor` / `major`). Then move the
  `Unreleased` entries in `CHANGELOG.md` under the new version; a test fails if the
  current version has no changelog entry.
- **Releasing:** tag the release commit `vX.Y.Z` on `main` and replace the date in its
  changelog heading. Never reuse a version number: the Test Suite records the exact
  version string with every scored run.
- **Every user-visible change** adds a line under `Unreleased` in `CHANGELOG.md`.

## Rules

- **Never name the external projects we studied for ideas.** That applies to commits,
  branch names, pull requests, issues, code comments, docs, plans, release notes and
  anything else we publish. We take ideas, not code. Tools and libraries we actually
  depend on (LangGraph, sqlmap, OSV-Scanner and so on) are named normally where they're
  used, as their licenses require.
- **Don't copy code from other projects.** If copying ever seems necessary, stop and
  check with Rushi first: the source's license would then require attribution.
- **Commits:** `type(scope): description`, where type is one of feat, fix, refactor,
  docs, test, chore, perf or ci.
- **Never add an AI agent as co-author.** No `Co-Authored-By:` trailers (or similar
  credit lines) for Claude or any other coding agent in commits, pull requests or tags.
- **Verdicts come from the harness.** Only `lynx.proof` and the fix verifier set
  `proven` or `verified`; nothing the model writes can.
- **Never commit secrets** or `.env` files, and never log prompts, API keys or tokens.
- **Configuration comes from `LYNX_*` environment variables only.** Lynx never
  loads a `.env` file, because the repository it scans must not be able to change
  its behavior. Document every new setting in `.env.example`.
- **Test only authorized targets.** Tests and local runs use localhost fixtures.
