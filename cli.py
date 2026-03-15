"""CLI entry point for FirmwareScan."""

from __future__ import annotations
from extractors import HeaderExtractor, CMakeExtractor, BinaryExtractor, MakefileExtractor
from report import *
from nvd import *

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="firmwarescan",
        description="Firmware dependency vulnerability scanner for embedded C/C++ projects.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to the firmware project root.",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        help="Output format.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        dest="fail_on",
        help="Exit with non-zero if findings at or above this severity are found.",
    )
    parser.add_argument(
        "--config",
        help="Path to configuration file.",
    )
    parser.add_argument(
        "--output",
        help="Write output to a file instead of stdout (JSON mode only).",
    )

    args = parser.parse_args()
    _run_scan(args)


def _run_scan(args: argparse.Namespace) -> None:
    dependencies: list[Dependency] = []
    findings: list[Finding] = []
    dependencies.extend(HeaderExtractor().extract(args.path))
    dependencies.extend(CMakeExtractor().extract(args.path))
    dependencies.extend(BinaryExtractor().extract(args.path))
    dependencies.extend(MakefileExtractor().extract(args.path))

    findings.extend(lookup(dependency) for dependency in dependencies)
    if args.format == "terminal":
        render_terminal(dependencies, findings)
    elif args.format == "json":
        render_json(dependencies, findings)
    else:
        raise ValueError(f"Invalid format: {args.format}")

if __name__ == "__main__":
    main()
