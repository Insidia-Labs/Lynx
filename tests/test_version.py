import re
import tomllib
from pathlib import Path

import lynx

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
CHANGELOG = PYPROJECT.parent / "CHANGELOG.md"
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def _declared_version() -> str:
    project = tomllib.loads(PYPROJECT.read_text())["project"]
    declared = project["version"]
    assert isinstance(declared, str)
    return declared


def test_package_version_matches_pyproject() -> None:
    assert lynx.__version__ == _declared_version()


def test_version_is_semver() -> None:
    assert SEMVER.match(_declared_version())


def test_changelog_has_an_entry_for_the_current_version() -> None:
    assert f"## [{_declared_version()}]" in CHANGELOG.read_text()
