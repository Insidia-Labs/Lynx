from pathlib import Path

import pytest
from pydantic import ValidationError

from lynx.config import Settings
from lynx.core.findings import FindingState


def test_defaults() -> None:
    settings = Settings()

    assert settings.tool_name == "Lynx"
    assert settings.information_uri == "https://insidialabs.com"
    assert settings.reported_states == {FindingState.PROVEN, FindingState.CORROBORATED}


def test_environment_overrides_the_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LYNX_TOOL_NAME", "Lynx CI")
    monkeypatch.setenv("LYNX_INFORMATION_URI", "https://example.test")
    monkeypatch.setenv("LYNX_REPORTED_STATES", '["proven", "corroborated", "candidate"]')

    settings = Settings()

    assert settings.tool_name == "Lynx CI"
    assert settings.information_uri == "https://example.test"
    assert FindingState.CANDIDATE in settings.reported_states


def test_unknown_finding_states_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LYNX_REPORTED_STATES", '["verified"]')

    with pytest.raises(ValidationError):
        Settings()


def test_settings_are_immutable() -> None:
    settings = Settings()

    with pytest.raises(ValidationError):
        settings.tool_name = "changed"  # type: ignore[misc]


def test_a_dotenv_file_in_the_scanned_folder_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text("LYNX_REPORTED_STATES=[]\nLYNX_TOOL_NAME=planted\n")
    monkeypatch.chdir(tmp_path)

    settings = Settings()

    assert settings.tool_name == "Lynx"
    assert settings.reported_states == {FindingState.PROVEN, FindingState.CORROBORATED}


def test_detector_timeout_defaults_to_ten_minutes_and_can_be_overridden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert Settings().detector_timeout == 600

    monkeypatch.setenv("LYNX_DETECTOR_TIMEOUT", "30")

    assert Settings().detector_timeout == 30


def test_detector_timeout_must_be_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LYNX_DETECTOR_TIMEOUT", "0")

    with pytest.raises(ValidationError):
        Settings()


def test_run_state_lives_in_the_user_state_folder_unless_overridden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LYNX_STATE_DIR")
    assert Settings().state_dir == Path.home() / ".local" / "state" / "lynx"

    monkeypatch.setenv("LYNX_STATE_DIR", str(tmp_path))

    assert Settings().state_dir == tmp_path
