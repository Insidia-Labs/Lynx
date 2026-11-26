import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from lynx.config import Settings

# A stand-in for a detector binary: it records its arguments, optionally sleeps,
# writes a report to the path after `flag` if one is given, then exits.
_FAKE_TOOL = """
import json, sys, time
args = sys.argv[1:]
open({args_file}, "w").write(json.dumps(args))
time.sleep({sleep})
if {report} is not None:
    open(args[args.index({flag}) + 1], "w").write({report})
sys.stderr.write({stderr})
sys.exit({exit_code})
"""

FakeTool = Callable[..., Path]


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep run checkpoints out of the real state folder, in this process and in children."""
    folder = tmp_path / "state"
    monkeypatch.setenv("LYNX_STATE_DIR", str(folder))
    monkeypatch.setattr("lynx.cli.settings", Settings())
    return folder


@pytest.fixture
def fake_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeTool:
    """Puts only fake tools on PATH. Returns a maker that gives back the args file."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir))

    def make(
        name: str,
        flag: str,
        report: str | None = None,
        exit_code: int = 0,
        stderr: str = "",
        sleep: float = 0,
    ) -> Path:
        args_file = tmp_path / f"{name}.args.json"
        body = _FAKE_TOOL.format(
            args_file=repr(str(args_file)),
            sleep=sleep,
            report=repr(report),
            flag=repr(flag),
            stderr=repr(stderr),
            exit_code=exit_code,
        )
        script = bin_dir / name
        script.write_text(f"#!{sys.executable}\n{body}")
        script.chmod(0o755)
        return args_file

    return make


@pytest.fixture
def source(tmp_path: Path) -> Path:
    """An empty folder to scan."""
    folder = tmp_path / "repo"
    folder.mkdir()
    return folder
