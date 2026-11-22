import runpy

import pytest

from lynx import __version__
from lynx.cli import main


def test_version_flag_prints_the_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"lynx {__version__}"


def test_no_arguments_prints_help_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: lynx" in capsys.readouterr().out


def test_module_entry_point_runs_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["lynx", "--version"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("lynx", run_name="__main__")

    assert exit_info.value.code == 0
