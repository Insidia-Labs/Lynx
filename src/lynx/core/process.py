"""Run external tools with a stripped environment and a hard timeout.

Detectors are third-party programs, so they get only the environment variables
they need to run. Lynx's own secrets (model API keys, tokens) stay out of their
reach. The allow-list is fixed in code, not a setting, for the same reason.
"""

import os
import signal
import subprocess
from dataclasses import dataclass

_ALLOWED_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
)


@dataclass(frozen=True)
class ToolRun:
    exit_code: int | None  # None when the tool was killed for running too long
    stdout: str
    stderr: str


def run_tool(argv: list[str], timeout: float) -> ToolRun:
    """Run a tool with no shell and no stdin; kill it and its children after `timeout` seconds."""
    env = {name: os.environ[name] for name in _ALLOWED_ENV if name in os.environ}
    with subprocess.Popen(  # noqa: S603 - argv is built by Lynx's detectors, never a shell string
        argv,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            return ToolRun(None, stdout, stderr)
        except BaseException:
            # Ctrl-C or SIGTERM stops Lynx, but the tool runs in its own session and
            # never sees the signal, so stop it here rather than leave it running.
            os.killpg(process.pid, signal.SIGKILL)
            raise
    return ToolRun(process.returncode, stdout, stderr)
