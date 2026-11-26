"""Lynx configuration.

Format constants are fixed: they describe the SARIF the code writes, so they only
change when that code does. Settings have defaults that environment variables
prefixed `LYNX_` can override (see `.env.example`).

Lynx never loads a `.env` file. It runs inside the repository it scans, and that
repository must not be able to change how Lynx behaves, for example by hiding
findings. Model API keys stay in the providers' own variables (`ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`); no Lynx setting holds a key.
"""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from lynx.core.findings import FindingState

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SOURCE_ROOT = "%SRCROOT%"

# Exit codes follow the Test Suite contract: 0 whenever a scan finished, whatever it
# found; non-zero only when it didn't (a partial scan still finished).
EXIT_FINISHED = 0
EXIT_NOT_FINISHED = 2
EXIT_CHECK_FAILED = 1  # `lynx doctor` found a problem

# `lynx doctor` asks each model for one tool call. Only the tokens it generates are
# billed, so the cap leaves room for thinking at no cost.
MODEL_CHECK_MAX_TOKENS = 4096
MODEL_CHECK_TIMEOUT = 60  # seconds


class ModelSpec(BaseModel):
    """The chat model for one role."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: Literal["anthropic", "openai"]  # openai means any OpenAI-compatible API
    name: str = Field(min_length=1)
    base_url: str | None = None  # None means the provider's own API


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LYNX_", env_nested_delimiter="__", frozen=True, extra="forbid"
    )

    tool_name: str = "Lynx"
    information_uri: str = "https://insidialabs.com"
    reported_states: frozenset[FindingState] = frozenset(
        {FindingState.PROVEN, FindingState.CORROBORATED}
    )
    detector_timeout: float = Field(default=600, gt=0)  # seconds per detector run
    # Run checkpoints, so an interrupted scan can be resumed.
    state_dir: Path = Path.home() / ".local" / "state" / "lynx"
    # One chat model per role: a cheaper one to map and to filter candidates, the
    # strongest to investigate and fix.
    map_model: ModelSpec = ModelSpec(provider="anthropic", name="claude-sonnet-5-5")
    investigate_model: ModelSpec = ModelSpec(provider="anthropic", name="claude-opus-5-5")
    skeptic_model: ModelSpec = ModelSpec(provider="anthropic", name="claude-sonnet-5-5")
    fix_model: ModelSpec = ModelSpec(provider="anthropic", name="claude-opus-5-5")


settings = Settings()
