import importlib
from pathlib import Path

import pytest

PACKAGES = [
    "lynx.core",
    "lynx.engine",
    "lynx.engine.nodes",
    "lynx.agent",
    "lynx.agent.tools",
    "lynx.codegraph",
    "lynx.detectors",
    "lynx.proof",
    "lynx.proof.provers",
    "lynx.fixer",
    "lynx.fixer.emit",
    "lynx.sandbox",
    "lynx.ai",
    "lynx.baseline",
    "lynx.agents",
    "lynx.memory",
    "lynx.mcp",
]


@pytest.mark.parametrize("name", PACKAGES)
def test_each_package_imports_and_says_what_it_is_for(name: str) -> None:
    module = importlib.import_module(name)

    assert module.__doc__, f"{name} needs a docstring describing its purpose"


def test_skills_folder_ships_with_the_package() -> None:
    import lynx

    skills = Path(lynx.__file__).parent / "skills"

    assert (skills / "README.md").is_file()
