"""Command line shared by the platform wrappers and installed console script."""

import argparse
import os
import signal
from pathlib import Path
import sys

from . import __version__


def main(argv=None):
    try:
        from .config import TOOLS, ScanError, load
    except ModuleNotFoundError as error:
        if error.name != "yaml":
            raise
        print('Install secscan dependencies first with: python -m pip install .', file=sys.stderr)
        return 3
    from .engine import scan
    from .reports import Redactor

    def tool_list(value):
        items = list(dict.fromkeys(part.strip().lower() for part in value.split(",")))
        if any(part not in TOOLS for part in items):
            raise argparse.ArgumentTypeError("choose from " + ", ".join(TOOLS))
        return items

    lock = load("tools.lock")
    version = " · ".join([f"secscan {__version__}", *[f"{tool} {lock[tool]['pinned']}" for tool in TOOLS]])
    parser = argparse.ArgumentParser(prog="secscan")
    parser.add_argument("--version", action="version", version=version, help="print the engine and pinned scanner versions")
    actions = parser.add_subparsers(dest="action", required=True)
    command = actions.add_parser("scan", help="scan a project directory")
    command.add_argument("project", nargs="?", type=Path, default=Path.cwd())
    command.add_argument("--config", type=Path)
    command.add_argument("--only", type=tool_list)
    command.add_argument("--skip", type=tool_list)
    command.add_argument("--timeout")
    command.add_argument("--build", action="store_true")
    command.add_argument("--no-fail", action="store_true")
    command.add_argument("--self-test", action="store_true")
    command.add_argument("--version", action="version", version=version, help="print the engine and pinned scanner versions")
    actions.add_parser("self-test", help="verify the installed scanners against the demo")
    dashboard = actions.add_parser("ui", help="open the local dashboard")
    dashboard.add_argument("--no-browser", action="store_true", help="print the opening URL without opening it")
    args = parser.parse_args(argv)
    if args.action == "ui":
        from .ui import launch
        return launch(args.no_browser)
    if os.environ.get("SECSCAN_RUN_ID") and os.name != "nt":
        signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        if args.action == "self-test" or args.self_test:
            from .selftest import self_test
            return self_test()
        return scan(args.project, args)
    except (ScanError, OSError) as error:
        print(Redactor().text(f"Scan could not finish: {error}"), file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("Scan interrupted", file=sys.stderr)
        return 130
