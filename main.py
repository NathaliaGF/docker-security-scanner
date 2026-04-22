#!/usr/bin/env python3
"""
docker-security-scanner — CLI entry point.

Usage:
    python main.py --file docker-compose.yml
    python main.py --dir ./my-project --severity HIGH
    python main.py --file Dockerfile --output json
"""

import argparse
import os
import sys

from scanner.compose_scanner import scan_compose
from scanner.dockerfile_scanner import scan_dockerfile
from scanner.report import print_report, export_json


# ── File-type detection ───────────────────────────────────────────────────────

def _detect_type(path: str) -> str:
    """Return 'compose', 'dockerfile', or 'unknown'."""
    name = os.path.basename(path).lower()

    if "docker-compose" in name or name in ("compose.yml", "compose.yaml"):
        return "compose"
    if "dockerfile" in name:
        return "dockerfile"

    # Peek at the first 1 KB of content as a fallback heuristic.
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            head = fh.read(1024)
        if "services:" in head and ("image:" in head or "build:" in head):
            return "compose"
        if head.lstrip().startswith("FROM ") or "\nFROM " in head:
            return "dockerfile"
    except OSError:
        pass

    return "unknown"


# ── Scanning helpers ──────────────────────────────────────────────────────────

def _scan_one(path: str, fmt: str, severity: str | None) -> int:
    """
    Scan a single file and emit output.
    Returns the number of HIGH-severity findings (used as exit-code signal).
    """
    file_type = _detect_type(path)

    try:
        if file_type == "compose":
            findings = scan_compose(path)
        elif file_type == "dockerfile":
            findings = scan_dockerfile(path)
        else:
            print(
                f"[WARN] Cannot determine file type for '{path}' — skipping.",
                file=sys.stderr,
            )
            return 0
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 0

    if fmt == "json":
        print(export_json(path, findings, severity))
    else:
        print_report(path, findings, severity)

    return sum(1 for f in findings if f.severity == "HIGH")


def _collect_targets(directory: str) -> list[str]:
    """Walk *directory* and return every file that looks like a Docker artifact."""
    targets: list[str] = []
    for root, _, files in os.walk(directory):
        for fname in files:
            full = os.path.join(root, fname)
            if _detect_type(full) != "unknown":
                targets.append(full)
    return sorted(targets)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docker-security-scanner",
        description="Analyse Dockerfiles and docker-compose files for security issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --file docker-compose.yml\n"
            "  python main.py --dir ./my-project --severity HIGH\n"
            "  python main.py --file Dockerfile --output json\n"
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", "-f", metavar="PATH", help="Single file to scan.")
    source.add_argument("--dir",  "-d", metavar="DIR",  help="Directory to scan recursively.")

    parser.add_argument(
        "--output", "-o",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["HIGH", "MEDIUM", "LOW"],
        default=None,
        metavar="LEVEL",
        help="Show only findings at this severity level (HIGH | MEDIUM | LOW).",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    total_high = 0

    if args.file:
        if not os.path.isfile(args.file):
            print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
            sys.exit(2)
        total_high += _scan_one(args.file, args.output, args.severity)

    else:  # --dir
        if not os.path.isdir(args.dir):
            print(f"[ERROR] Directory not found: {args.dir}", file=sys.stderr)
            sys.exit(2)

        targets = _collect_targets(args.dir)
        if not targets:
            print(f"No Dockerfiles or docker-compose files found in '{args.dir}'.")
            sys.exit(0)

        for path in targets:
            total_high += _scan_one(path, args.output, args.severity)

    # Non-zero exit code when HIGH findings are present — useful in CI pipelines.
    sys.exit(1 if total_high > 0 else 0)


if __name__ == "__main__":
    main()
