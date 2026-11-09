"""
Scans docker-compose.yml files for security misconfigurations (DC001–DC010).
"""

import re
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from . import Finding
from .rules import COMPOSE_RULES

# Environment variable names that suggest a secret value is present.
# No \b anchors: underscore is a word char in Python, so \bSECRET\b would
# miss names like SECRET_KEY or POSTGRES_PASSWORD.
_SECRET_NAME_RE = re.compile(
    r"(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|CREDENTIALS|PRIVATE_KEY)",
    re.IGNORECASE,
)

# Capabilities that grant near-root access.
_DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"}


# ── Public API ────────────────────────────────────────────────────────────────

def scan_compose(file_path: str) -> list[Finding]:
    """
    Parse *file_path* as a docker-compose YAML file and return all findings.

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError: if the YAML is malformed or has an unexpected root type.
        RuntimeError: if pyyaml is not installed.
    """
    if yaml is None:
        raise RuntimeError("pyyaml is required. Run: pip install pyyaml")

    try:
        with open(file_path, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}") from None

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse YAML in '{file_path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"'{file_path}' does not appear to be a valid docker-compose file "
            "(root element must be a YAML mapping)."
        )

    lines = raw.splitlines()
    services: dict = data.get("services") or {}
    findings: list[Finding] = []

    for service_name, service_cfg in services.items():
        if not isinstance(service_cfg, dict):
            continue
        findings.extend(_check_dc001(service_name, service_cfg, lines))
        findings.extend(_check_dc002(service_name, service_cfg, lines))
        findings.extend(_check_dc003(service_name, service_cfg, lines))
        findings.extend(_check_dc004(service_name, service_cfg, lines))
        findings.extend(_check_dc005(service_name, service_cfg, lines))
        findings.extend(_check_dc006(service_name, service_cfg, lines))
        findings.extend(_check_dc007(service_name, service_cfg, lines))
        findings.extend(_check_dc008(service_name, service_cfg, lines))
        findings.extend(_check_dc009(service_name, service_cfg, lines))
        findings.extend(_check_dc010(service_name, service_cfg, lines))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_line(lines: list[str], pattern: str, start: int = 0) -> Optional[int]:
    """Return the 1-based line number of the first line containing *pattern*."""
    for i, line in enumerate(lines[start:], start=start + 1):
        if pattern in line:
            return i
    return None


def _make(rule_id: str, service: str, line: Optional[int]) -> Finding:
    rule = COMPOSE_RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        severity=rule.severity,
        description=rule.description,
        detail=rule.detail,
        fix=rule.fix,
        service=service,
        line=line,
    )


# ── Checks ────────────────────────────────────────────────────────────────────

def _check_dc001(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC001 — Container running as root."""
    user = cfg.get("user")
    if user is None or str(user).strip() in ("root", "0", "0:0"):
        return [_make("DC001", name, _find_line(lines, f"  {name}:"))]
    return []


def _check_dc002(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC002 — Privileged port (< 1024) mapped to the host."""
    for port in cfg.get("ports", []):
        port_str = str(port)
        parts = port_str.split(":")
        if len(parts) < 2:
            # Format "container_port" — Docker picks a random host port; skip.
            continue
        # Formats: "host:container" or "ip:host:container"
        host_part = parts[-2].split("/")[0]
        try:
            if int(host_part) < 1024:
                return [_make("DC002", name, _find_line(lines, port_str))]
        except ValueError:
            pass
    return []


def _check_dc003(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC003 — Image with `latest` tag or no tag at all."""
    image: str = cfg.get("image", "")
    if not image:
        return []
    tag = image.split(":")[-1] if ":" in image else "latest"
    if tag == "latest" or ":" not in image:
        return [_make("DC003", name, _find_line(lines, f"image: {image}"))]
    return []


def _check_dc004(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC004 — Sensitive host path mounted (/, /etc, /var/run/docker.sock)."""
    dangerous = {"/", "/etc", "/var/run/docker.sock"}
    for vol in cfg.get("volumes", []):
        if isinstance(vol, dict):
            source = vol.get("source", "")
        else:
            source = str(vol).split(":")[0]
        if source in dangerous:
            return [_make("DC004", name, _find_line(lines, source))]
    return []


def _check_dc005(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC005 — Plaintext secret in an environment variable."""
    environment = cfg.get("environment", {})
    pairs: list[str] = (
        environment
        if isinstance(environment, list)
        else [f"{k}={v}" for k, v in environment.items()]
    )
    for entry in pairs:
        entry_str = str(entry)
        if "=" not in entry_str:
            continue
        key, _, value = entry_str.partition("=")
        if _SECRET_NAME_RE.search(key) and value.strip():
            return [_make("DC005", name, _find_line(lines, key.strip()))]
    return []


def _check_dc006(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC006 — `restart: always` without a health check."""
    if cfg.get("restart") == "always" and cfg.get("healthcheck") is None:
        return [_make("DC006", name, _find_line(lines, "restart: always"))]
    return []


def _check_dc007(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC007 — `privileged: true`."""
    if cfg.get("privileged") is True:
        return [_make("DC007", name, _find_line(lines, "privileged: true"))]
    return []


def _check_dc008(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC008 — Host network mode."""
    if cfg.get("network_mode") == "host":
        return [_make("DC008", name, _find_line(lines, "network_mode: host"))]
    return []


def _check_dc009(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC009 — No CPU or memory limits defined."""
    has_mem = "mem_limit" in cfg
    has_cpu = "cpus" in cfg

    # Also honour Compose v3 deploy.resources.limits block.
    deploy = cfg.get("deploy") or {}
    limits = (deploy.get("resources") or {}).get("limits") or {}
    has_mem = has_mem or "memory" in limits
    has_cpu = has_cpu or "cpus" in limits

    if not has_mem and not has_cpu:
        return [_make("DC009", name, _find_line(lines, f"  {name}:"))]
    return []


def _check_dc010(name: str, cfg: dict, lines: list[str]) -> list[Finding]:
    """DC010 — Dangerous Linux capabilities added (ALL, SYS_ADMIN, NET_ADMIN…)."""
    for cap in cfg.get("cap_add", []):
        if str(cap).upper() in _DANGEROUS_CAPS:
            return [_make("DC010", name, _find_line(lines, str(cap)))]
    return []
