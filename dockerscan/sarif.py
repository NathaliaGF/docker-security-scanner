"""
SARIF 2.1.0 and Markdown exporters.

SARIF is what GitHub code scanning ingests: uploading it makes findings show
up in the repository's Security tab and as annotations on pull requests.
"""

import os
from typing import Optional

from . import Finding, __version__
from .references import cis_reference
from .rules import COMPOSE_RULES, DOCKERFILE_RULES

_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
# GitHub maps `security-severity` to Critical/High/Medium/Low buckets.
_SECURITY_SEVERITY = {"HIGH": "8.0", "MEDIUM": "5.0", "LOW": "3.0"}
_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_ICON = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}

Result = tuple[str, list[Finding]]


def _uri(path: str) -> str:
    return os.path.relpath(path).replace(os.sep, "/")


def _rule_descriptors() -> list[dict]:
    descriptors = []
    for rule in {**COMPOSE_RULES, **DOCKERFILE_RULES}.values():
        tags = ["security", "docker"]
        cis = cis_reference(rule.id)
        if cis:
            tags.append("cis-docker-benchmark")
        descriptors.append({
            "id": rule.id,
            "name": rule.description,
            "shortDescription": {"text": rule.description},
            "fullDescription": {"text": rule.detail},
            "help": {
                "text": f"{rule.fix}" + (f"\n{cis}" if cis else ""),
                "markdown": f"**How to fix:** {rule.fix}" + (f"\n\n{cis}" if cis else ""),
            },
            "defaultConfiguration": {"level": _LEVEL[rule.severity]},
            "properties": {
                "tags": tags,
                "security-severity": _SECURITY_SEVERITY[rule.severity],
            },
        })
    return descriptors


def to_sarif(results: list[Result], severity_filter: Optional[str] = None) -> dict:
    """Build a SARIF log for the given (path, findings) pairs."""
    sarif_results = []
    for path, findings in results:
        for f in findings:
            if severity_filter and f.severity != severity_filter.upper():
                continue
            message = f.description
            if f.service:
                message += f" (service: {f.service})"
            message += f". Fix: {f.fix}"
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": _LEVEL[f.severity],
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(path)},
                        "region": {"startLine": f.line or 1},
                    }
                }],
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "dockerscan",
                    "version": __version__,
                    "informationUri": "https://github.com/NathaliaGF/docker-security-scanner",
                    "rules": _rule_descriptors(),
                }
            },
            "results": sarif_results,
        }],
    }


def to_markdown(results: list[Result], severity_filter: Optional[str] = None) -> str:
    """Render results as Markdown (PR comments, $GITHUB_STEP_SUMMARY)."""
    from .report import compute_score

    lines = ["## 🐳 dockerscan report", ""]
    total = 0
    for path, findings in results:
        shown = [f for f in findings
                 if not severity_filter or f.severity == severity_filter.upper()]
        shown.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        total += len(findings)
        lines.append(f"### `{_uri(path)}`: score {compute_score(findings)}/100")
        lines.append("")
        if not shown:
            lines += ["✅ No findings.", ""]
            continue
        lines += ["| Severity | Rule | Where | Issue | Fix |", "|---|---|---|---|---|"]
        for f in shown:
            if f.service and f.line:
                where = f"{f.service}:{f.line}"
            elif f.service:
                where = f.service
            elif f.line:
                where = f"L{f.line}"
            else:
                where = "-"
            desc = f.description.replace("|", "\\|")
            fix = f.fix.replace("|", "\\|")
            lines.append(
                f"| {_ICON.get(f.severity, '')} {f.severity} | `{f.rule_id}` | {where} "
                f"| {desc} | {fix} |"
            )
        lines.append("")
    lines.append(f"**{total} finding{'s' if total != 1 else ''} in {len(results)} file(s).**")
    return "\n".join(lines) + "\n"
