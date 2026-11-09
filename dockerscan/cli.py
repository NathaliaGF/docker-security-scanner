"""
dockerscan command line interface.

    dockerscan --file docker-compose.yml
    dockerscan --dir ./my-project --output sarif > results.sarif
    dockerscan --file Dockerfile --explain --lang pt
    dockerscan --file Dockerfile --fix          # show a validated diff
    dockerscan --file Dockerfile --fix --apply  # and write it
"""

import argparse
import json
import os
import sys

from . import Finding, __version__
from .ai import DEFAULT_MODEL, AIUnavailable, explain, make_client, propose_fix
from .core import collect_targets, scan_file
from .references import cis_reference
from .report import export_json, export_json_multi, print_report
from .rules import COMPOSE_RULES, DOCKERFILE_RULES
from .sarif import to_markdown, to_sarif

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dockerscan",
        description="Static security scanner for Dockerfiles and docker-compose files, "
                    "with optional AI explanations and validated auto-fixes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  dockerscan --file docker-compose.yml\n"
            "  dockerscan --dir ./my-project --severity HIGH\n"
            "  dockerscan --dir . --output sarif > results.sarif\n"
            "  dockerscan --file Dockerfile --explain --lang pt\n"
            "  dockerscan --file Dockerfile --fix --apply\n"
        ),
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--file", "-f", metavar="PATH", help="Single file to scan.")
    source.add_argument("--dir", "-d", metavar="DIR", help="Directory to scan recursively.")
    source.add_argument("--list-rules", action="store_true", help="List all rules and exit.")

    parser.add_argument("--output", "-o", choices=["terminal", "json", "sarif", "markdown"],
                        default="terminal", help="Output format (default: terminal).")
    parser.add_argument("--severity", "-s", choices=["HIGH", "MEDIUM", "LOW"], default=None,
                        metavar="LEVEL", help="Show only findings at this severity.")
    parser.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW", "none"], default="HIGH",
                        help="Exit 1 when a finding at or above this severity exists "
                             "(default: HIGH).")

    ai = parser.add_argument_group("AI (optional, needs ANTHROPIC_API_KEY)")
    ai.add_argument("--explain", action="store_true",
                    help="Explain each finding in context with Claude.")
    ai.add_argument("--fix", action="store_true",
                    help="Ask Claude for a fix, re-scan it, and show the diff if it passes.")
    ai.add_argument("--apply", action="store_true",
                    help="With --fix: write the validated fix to the file.")
    ai.add_argument("--lang", choices=["en", "pt"], default=os.environ.get("DOCKERSCAN_LANG", "en"),
                    help="Language of AI explanations (default: en).")
    ai.add_argument("--model", default=os.environ.get("DOCKERSCAN_MODEL", DEFAULT_MODEL),
                    help=f"Claude model (default: {DEFAULT_MODEL}).")
    parser.add_argument("--version", action="version", version=f"dockerscan {__version__}")
    return parser


def _list_rules() -> None:
    for rule in sorted({**COMPOSE_RULES, **DOCKERFILE_RULES}.values(), key=lambda r: r.id):
        cis = cis_reference(rule.id)
        print(f"{rule.id}  {rule.severity:<6}  {rule.description}" + (f"  [{cis.split(':')[0]}]" if cis else ""))


def _run_ai(path: str, findings: list[Finding], args: argparse.Namespace, client) -> None:
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    if args.explain:
        print("🤖 Explanation\n" + "─" * 58)
        print(explain(path, content, findings, client, args.model, args.lang).strip() + "\n")
    if args.fix:
        result = propose_fix(path, content, findings, client, args.model)
        print("🔧 Proposed fix\n" + "─" * 58)
        if result.accepted:
            print(result.diff)
            print(f"✅ Re-scan: {len(result.before)} → {len(result.after)} findings "
                  f"(no new rules introduced, {result.attempts} attempt(s)).")
            if args.apply:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(result.fixed)
                print(f"💾 Applied to {path}")
            else:
                print("Run again with --apply to write it.")
        else:
            why = result.reason or (f"new rules introduced: {sorted(result.introduced)}"
                                    if result.introduced else "no improvement")
            print(f"⚠️  Fix rejected, file untouched ({why}).")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        _list_rules()
        return 0
    if not (args.file or args.dir):
        parser.error("one of --file or --dir is required")
    if (args.explain or args.fix) and args.output != "terminal":
        parser.error("--explain/--fix only work with --output terminal")
    if args.apply and not args.fix:
        parser.error("--apply requires --fix")

    if args.file:
        if not os.path.isfile(args.file):
            print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
            return 2
        targets = [args.file]
    else:
        if not os.path.isdir(args.dir):
            print(f"[ERROR] Directory not found: {args.dir}", file=sys.stderr)
            return 2
        targets = collect_targets(args.dir)
        if not targets:
            print(f"No Dockerfiles or docker-compose files found in '{args.dir}'.")
            return 0

    client = None
    if args.explain or args.fix:
        try:
            client = make_client()
        except AIUnavailable as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2

    results: list[tuple[str, list[Finding]]] = []
    for path in targets:
        try:
            results.append((path, scan_file(path)))
        except ValueError as exc:
            print(f"[WARN] {exc} Skipping.", file=sys.stderr)
        except (FileNotFoundError, RuntimeError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)

    if args.output == "json":
        print(export_json(*results[0], args.severity) if args.file and results
              else export_json_multi(results, args.severity))
    elif args.output == "sarif":
        print(json.dumps(to_sarif(results, args.severity), indent=2))
    elif args.output == "markdown":
        print(to_markdown(results, args.severity), end="")
    else:
        for path, findings in results:
            print_report(path, findings, args.severity)
            if client and findings:
                try:
                    _run_ai(path, findings, args, client)
                except Exception as exc:  # network/API errors must not hide the scan result
                    print(f"[ERROR] AI step failed: {exc}", file=sys.stderr)

    if args.fail_on == "none":
        return 0
    threshold = _SEVERITY_RANK[args.fail_on]
    failed = any(_SEVERITY_RANK.get(f.severity, 0) >= threshold
                 for _, findings in results for f in findings)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
