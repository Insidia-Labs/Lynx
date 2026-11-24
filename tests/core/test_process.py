import json
import sys
import time
from pathlib import Path

import pytest

from lynx.core.process import run_tool


def _python(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_output_and_exit_code_are_captured() -> None:
    run = run_tool(
        _python("import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"),
        timeout=10,
    )

    assert run.exit_code == 3
    assert run.stdout == "out\n"
    assert run.stderr == "err\n"


def test_secrets_in_the_environment_never_reach_the_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-for-tools")
    monkeypatch.setenv("GITHUB_TOKEN", "not-for-tools")

    run = run_tool(_python("import json, os; print(json.dumps(sorted(os.environ)))"), timeout=10)

    names = set(json.loads(run.stdout))
    assert "ANTHROPIC_API_KEY" not in names
    assert "GITHUB_TOKEN" not in names
    assert "PATH" in names


def test_the_tool_gets_no_stdin() -> None:
    run = run_tool(_python("import sys; print(repr(sys.stdin.read()))"), timeout=10)

    assert run.stdout.strip() == "''"


def test_a_tool_that_runs_too_long_is_killed() -> None:
    started = time.monotonic()

    run = run_tool(_python("import time; time.sleep(30)"), timeout=0.5)

    assert run.exit_code is None
    assert time.monotonic() - started < 10


def _alive(pid: int) -> bool:
    """Running, not a zombie. A process can vanish while we read its stat file."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split(") ")[-1][0]
    except FileNotFoundError, ProcessLookupError:
        return False
    return state != "Z"


@pytest.mark.skipif(not Path("/proc").is_dir(), reason="reads process state from /proc")
def test_child_processes_are_killed_with_the_tool(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
        "time.sleep(30)\n"
    )

    # Enough time for the tool to start its child and record the pid, even on a busy machine.
    run_tool(_python(code), timeout=3)

    child = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while _alive(child) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(child)
