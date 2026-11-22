"""The `lynx` command line."""

import argparse
from collections.abc import Sequence

from lynx import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lynx",
        description="AI security testing that proves what it finds and opens the fix.",
    )
    parser.add_argument("--version", action="version", version=f"lynx {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
