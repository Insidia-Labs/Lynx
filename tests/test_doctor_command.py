import pytest

from lynx.cli import main
from lynx.config import ModelSpec, Settings


def _check(problems: dict[str, str]) -> tuple[list[str], object]:
    """A stand-in for the live check: fails the named models, records each call."""
    calls: list[str] = []

    def check(spec: ModelSpec) -> str | None:
        calls.append(spec.name)
        return problems.get(spec.name)

    return calls, check


def test_every_role_passes_with_the_default_models(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls, check = _check({})
    monkeypatch.setattr("lynx.cli.check_tool_calling", check)

    assert main(["doctor"]) == 0

    assert capsys.readouterr().out.splitlines() == [
        "map: anthropic claude-sonnet-5-5: ok, calls tools",
        "investigate: anthropic claude-opus-5-5: ok, calls tools",
        "skeptic: anthropic claude-sonnet-5-5: ok, calls tools",
        "fix: anthropic claude-opus-5-5: ok, calls tools",
    ]
    assert calls == ["claude-sonnet-5-5", "claude-opus-5-5"], "a shared model is checked once"


def test_a_failing_model_fails_the_check_and_says_why(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, check = _check({"claude-opus-5-5": "the API rejected the key (check ANTHROPIC_API_KEY)"})
    monkeypatch.setattr("lynx.cli.check_tool_calling", check)

    assert main(["doctor"]) == 1

    out = capsys.readouterr().out
    assert "map: anthropic claude-sonnet-5-5: ok, calls tools" in out
    assert "fix: anthropic claude-opus-5-5: the API rejected the key" in out


def test_credentials_in_a_base_url_or_an_error_are_masked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    password = "hunter" + "22-local"
    key = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    local = ModelSpec(
        provider="openai", name="qwen3.5", base_url=f"http://lynx:{password}@localhost:8000/v1"
    )
    monkeypatch.setattr("lynx.cli.settings", Settings(map_model=local))
    _, check = _check({"qwen3.5": f"Incorrect API key provided: {key}"})
    monkeypatch.setattr("lynx.cli.check_tool_calling", check)

    main(["doctor"])

    out = capsys.readouterr().out
    assert "map: openai qwen3.5 at http://[REDACTED:URL_CREDENTIALS]@localhost:8000/v1:" in out
    assert password not in out
    assert key not in out
