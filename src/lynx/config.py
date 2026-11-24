"""Lynx configuration.

Format constants are fixed: they describe the SARIF the code writes, so they only
change when that code does. Settings have defaults that environment variables
prefixed `LYNX_` can override (see `.env.example`).

Lynx never loads a `.env` file. It runs inside the repository it scans, and that
repository must not be able to change how Lynx behaves, for example by hiding
findings.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from lynx.core.findings import FindingState

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SOURCE_ROOT = "%SRCROOT%"

# Exit codes follow the Test Suite contract: 0 whenever a scan finished, whatever it
# found; non-zero only when it didn't (a partial scan still finished).
EXIT_FINISHED = 0
EXIT_NOT_FINISHED = 2


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LYNX_", frozen=True, extra="forbid")

    tool_name: str = "Lynx"
    information_uri: str = "https://insidialabs.com"
    reported_states: frozenset[FindingState] = frozenset(
        {FindingState.PROVEN, FindingState.CORROBORATED}
    )
    detector_timeout: float = Field(default=600, gt=0)  # seconds per detector run


settings = Settings()
