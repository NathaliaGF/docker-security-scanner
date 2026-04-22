"""
Render security findings as a coloured terminal report or as JSON.
"""

import json
from typing import Optional

from . import Finding

try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _C_HIGH   = Fore.RED
    _C_MEDIUM = Fore.YELLOW
    _C_LOW    = Fore.CYAN
    _RESET    = Style.RESET_ALL
except ImportError:
    # Graceful fallback to raw ANSI escape codes.
    _C_HIGH   = "\033[91m"
    _C_MEDIUM = "\033[93m"
    _C_LOW    = "\033[96m"
    _RESET    = "\033[0m"

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_SEVERITY_COLOR = {"HIGH": _C_HIGH, "MEDIUM": _C_MEDIUM, "LOW": _C_LOW}
_SEVERITY_ICON  = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}

# Deduction per finding severity.
_DEDUCTIONS = {"HIGH": 15, "MEDIUM": 7, "LOW": 2}


# ── Public API ────────────────────────────────────────────────────────────────

def compute_score(findings: list[Finding]) -> int:
    """Compute a 0–100 security score; deductions apply to the unfiltered list."""
    score = 100
    for f in findings:
        score -= _DEDUCTIONS.get(f.severity, 0)
    return max(0, score)


def print_report(
    file_path: str,
    findings: list[Finding],
    severity_filter: Optional[str] = None,
) -> None:
    """Print a coloured terminal report for *findings*."""
    displayed = _filter_and_sort(findings, severity_filter)
    score     = compute_score(findings)          # always computed on full list
    summary   = _summarise(findings)

    _banner()
    print(f"\n📄 Arquivo: {file_path}")
    print("─" * 58)

    if not displayed:
        print("\n✅  Nenhum achado para o filtro selecionado.\n")
    else:
        print()
        for f in displayed:
            _print_finding(f)

    print("─" * 58)
    total = len(findings)
    h, m, l = summary["HIGH"], summary["MEDIUM"], summary["LOW"]
    print(f"RESUMO: {total} achado{'s' if total != 1 else ''}  |  "
          f"🔴 HIGH: {h}  |  🟡 MEDIUM: {m}  |  🔵 LOW: {l}")
    print(f"Score de segurança: {score}/100")
    print("─" * 58)
    print()


def export_json(
    file_path: str,
    findings: list[Finding],
    severity_filter: Optional[str] = None,
) -> str:
    """Return a JSON string representation of the scan report."""
    displayed = _filter_and_sort(findings, severity_filter)
    score     = compute_score(findings)
    summary   = _summarise(findings)

    findings_data = []
    for f in displayed:
        entry: dict = {
            "id":          f.rule_id,
            "severity":    f.severity,
            "description": f.description,
            "detail":      f.detail,
            "fix":         f.fix,
        }
        if f.service is not None:
            entry["service"] = f.service
        if f.line is not None:
            entry["line"] = f.line
        findings_data.append(entry)

    payload = {
        "file":           file_path,
        "score":          score,
        "total_findings": len(findings),
        "findings":       findings_data,
        "summary":        summary,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _filter_and_sort(
    findings: list[Finding],
    severity_filter: Optional[str],
) -> list[Finding]:
    if severity_filter:
        findings = [f for f in findings if f.severity == severity_filter.upper()]
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


def _summarise(findings: list[Finding]) -> dict[str, int]:
    return {
        "HIGH":   sum(1 for f in findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
        "LOW":    sum(1 for f in findings if f.severity == "LOW"),
    }


def _coloured(text: str, severity: str) -> str:
    return f"{_SEVERITY_COLOR.get(severity, '')}{text}{_RESET}"


def _banner() -> None:
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║           DOCKER SECURITY SCANNER — RELATÓRIO            ║")
    print("╚══════════════════════════════════════════════════════════╝")


def _print_finding(f: Finding) -> None:
    icon  = _SEVERITY_ICON.get(f.severity, "⚪")
    label = _coloured(f"[{f.severity:<6}]", f.severity)
    print(f"{icon} {label} {f.rule_id} — {f.description}")
    if f.service:
        print(f"            Serviço: {f.service}")
    if f.line:
        print(f"            Linha:   {f.line}")
    print(f"            Detalhe: {f.detail}")
    print(f"            Fix:     {f.fix}")
    print()
