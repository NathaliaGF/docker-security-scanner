"""
Scans Dockerfiles for security misconfigurations (DF001–DF010).
"""

import os
import re
from typing import Optional

from . import Finding
from .rules import DOCKERFILE_RULES

# Credential-related keyword pattern for ENV / ARG values.
# No \b anchors: underscore is a word char in Python regex, so \bSECRET\b
# would silently miss names like SECRET_KEY or DB_PASSWORD.
_CRED_RE = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIALS)",
    re.IGNORECASE,
)

# A value that is just a variable reference carries no secret itself.
_VAR_REF_RE = re.compile(r"^\$(\{[A-Za-z_][A-Za-z0-9_]*(:?[-?][^}]*)?\}|[A-Za-z_][A-Za-z0-9_]*)$")

# Private key / certificate file extensions or names.
_PRIVKEY_RE = re.compile(
    r"(\.pem|\.key|\.crt|\.cer|\.p12|\.pfx|id_rsa|id_dsa|id_ecdsa|id_ed25519|private_key)",
    re.IGNORECASE,
)

# Shell-piping pattern: curl/wget output piped straight into a shell or interpreter.
_PIPE_SHELL_RE = re.compile(
    r"(curl|wget)\s+.+\|\s*(bash|sh|python\d*|ruby|perl)",
    re.IGNORECASE,
)

# Ports that indicate a remote-access daemon (SSH, Telnet, RDP).
_SENSITIVE_PORTS = {22, 23, 3389}

# Known end-of-life base images.
_EOL_IMAGES = {
    "ubuntu:16.04", "ubuntu:14.04", "ubuntu:12.04",
    "debian:8", "debian:7", "debian:jessie", "debian:wheezy",
    "centos:6", "centos:5",
    "python:2.7", "python:2",
    "node:6", "node:8", "node:10",
    "alpine:3.6", "alpine:3.7", "alpine:3.8", "alpine:3.9",
}

# Maximum number of consecutive RUN instructions before we flag DF007.
_MAX_CONSECUTIVE_RUNS = 3


# ── Public API ────────────────────────────────────────────────────────────────

def scan_dockerfile(file_path: str) -> list[Finding]:
    """
    Read *file_path* as a Dockerfile and return all security findings.

    Raises:
        FileNotFoundError: if the file does not exist.
    """
    try:
        with open(file_path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}") from None

    # DF005 only applies when the build context is not filtered by a .dockerignore.
    has_dockerignore = os.path.isfile(
        os.path.join(os.path.dirname(os.path.abspath(file_path)), ".dockerignore")
    )

    findings: list[Finding] = []
    has_user = False          # tracks whether any USER instruction was seen
    in_continuation = False   # tracks backslash line-continuation
    consecutive_runs = 0
    run_streak_start = 0
    df007_reported = False

    for lineno, raw in enumerate(lines, start=1):
        stripped = raw.strip()

        # Skip empty lines and comments, but also reset continuation tracking.
        if not stripped or stripped.startswith("#"):
            continue

        # If the previous line ended with \, this line is a continuation —
        # it belongs to the same instruction.
        if in_continuation:
            in_continuation = raw.rstrip("\n").rstrip().endswith("\\")
            continue

        in_continuation = raw.rstrip("\n").rstrip().endswith("\\")
        upper = stripped.upper()

        # ── FROM ─────────────────────────────────────────────────────────────
        if upper.startswith("FROM ") or upper == "FROM":
            findings.extend(_check_df002(stripped, lineno))
            findings.extend(_check_df010(stripped, lineno))
            # A new build stage resets the consecutive-RUN counter.
            consecutive_runs = 0
            df007_reported = False

        # ── USER ─────────────────────────────────────────────────────────────
        elif upper.startswith("USER ") or upper == "USER":
            has_user = True
            findings.extend(_check_df001_explicit_root(stripped, lineno))
            consecutive_runs = 0
            df007_reported = False

        # ── ENV / ARG ────────────────────────────────────────────────────────
        elif upper.startswith("ENV ") or upper.startswith("ARG "):
            findings.extend(_check_df003(stripped, lineno))
            consecutive_runs = 0
            df007_reported = False

        # ── RUN ──────────────────────────────────────────────────────────────
        elif upper.startswith("RUN ") or upper == "RUN":
            findings.extend(_check_df004(stripped, lineno))
            findings.extend(_check_df006(stripped, lineno))

            consecutive_runs += 1
            if consecutive_runs == 1:
                run_streak_start = lineno
            if consecutive_runs > _MAX_CONSECUTIVE_RUNS and not df007_reported:
                findings.append(_make("DF007", run_streak_start))
                df007_reported = True

        # ── COPY ─────────────────────────────────────────────────────────────
        elif upper.startswith("COPY "):
            if not has_dockerignore:
                findings.extend(_check_df005(stripped, lineno))
            findings.extend(_check_df009(stripped, lineno))
            consecutive_runs = 0
            df007_reported = False

        # ── EXPOSE ───────────────────────────────────────────────────────────
        elif upper.startswith("EXPOSE ") or upper == "EXPOSE":
            findings.extend(_check_df008(stripped, lineno))
            consecutive_runs = 0
            df007_reported = False

        else:
            # Any other instruction breaks a RUN streak.
            consecutive_runs = 0
            df007_reported = False

    # DF001 — no USER instruction anywhere in the file.
    if not has_user:
        findings.append(_make("DF001", None))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make(rule_id: str, line: Optional[int]) -> Finding:
    rule = DOCKERFILE_RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        severity=rule.severity,
        description=rule.description,
        detail=rule.detail,
        fix=rule.fix,
        line=line,
    )


def _image_tag(instruction_line: str) -> tuple[str, str]:
    """Return (image, tag) parsed from a FROM instruction."""
    parts = instruction_line.split()
    image_ref = parts[1] if len(parts) > 1 else ""
    # Strip AS alias: FROM python:3.12 AS builder
    if len(parts) >= 4 and parts[2].upper() == "AS":
        image_ref = parts[1]
    image_lower = image_ref.lower()
    if ":" in image_lower:
        img, tag = image_lower.rsplit(":", 1)
    else:
        img, tag = image_lower, "latest"
    return img, tag


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_df001_explicit_root(line: str, lineno: int) -> list[Finding]:
    """DF001 — USER root or USER 0."""
    parts = line.split()
    user_val = parts[1].strip() if len(parts) > 1 else ""
    if user_val.lower() in ("root", "0", "0:0"):
        return [_make("DF001", lineno)]
    return []


def _check_df002(line: str, lineno: int) -> list[Finding]:
    """DF002 — Base image with `latest` tag or no tag."""
    _, tag = _image_tag(line)
    image_ref = line.split()[1] if len(line.split()) > 1 else ""
    if image_ref.lower() in ("scratch", ""):
        return []
    if tag == "latest" or ":" not in image_ref:
        return [_make("DF002", lineno)]
    return []


def _is_reference(value: str) -> bool:
    """True when *value* only points at another variable (`${DB_PASS}`, `$TOKEN`)."""
    return bool(_VAR_REF_RE.match(value.strip().strip("\"'")))


def _check_df003(line: str, lineno: int) -> list[Finding]:
    """DF003 — Hardcoded credential in ENV or ARG."""
    rest = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
    if not _CRED_RE.search(rest):
        return []
    # Only flag when there is a non-empty value (avoid flagging `ARG PASSWORD`
    # declarations without a default).
    if "=" in rest:
        _, _, value = rest.partition("=")
        if value.strip() and not _is_reference(value):
            return [_make("DF003", lineno)]
    else:
        # ENV KEY VALUE (space-separated) — two tokens after ENV = key + value.
        tokens = rest.strip().split()
        if len(tokens) >= 2 and _CRED_RE.search(tokens[0]) and not _is_reference(tokens[1]):
            return [_make("DF003", lineno)]
    return []


def _check_df004(line: str, lineno: int) -> list[Finding]:
    """DF004 — apt-get install without --no-install-recommends."""
    if "apt-get install" in line.lower() and "--no-install-recommends" not in line:
        return [_make("DF004", lineno)]
    return []


def _check_df005(line: str, lineno: int) -> list[Finding]:
    """DF005 — COPY . . (entire build context)."""
    parts = line.split()
    # COPY [--flag] src dst  — src is the second (or third after flags) token.
    src_candidates = [p for p in parts[1:] if not p.startswith("--")]
    if src_candidates and src_candidates[0] in (".", "./"):
        return [_make("DF005", lineno)]
    return []


def _check_df006(line: str, lineno: int) -> list[Finding]:
    """DF006 — Remote script piped into a shell (curl | bash)."""
    if _PIPE_SHELL_RE.search(line):
        return [_make("DF006", lineno)]
    return []


def _check_df008(line: str, lineno: int) -> list[Finding]:
    """DF008 — Sensitive port exposed (22, 23, 3389)."""
    for token in line.split()[1:]:
        port_str = token.split("/")[0]
        try:
            if int(port_str) in _SENSITIVE_PORTS:
                return [_make("DF008", lineno)]
        except ValueError:
            pass
    return []


def _check_df009(line: str, lineno: int) -> list[Finding]:
    """DF009 — Private key or certificate copied into the image."""
    if _PRIVKEY_RE.search(line):
        return [_make("DF009", lineno)]
    return []


def _check_df010(line: str, lineno: int) -> list[Finding]:
    """DF010 — Known end-of-life base image."""
    _, tag_part = _image_tag(line)
    parts = line.split()
    image_ref = parts[1].lower() if len(parts) > 1 else ""
    if image_ref in _EOL_IMAGES:
        return [_make("DF010", lineno)]
    return []
