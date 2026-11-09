"""dockerscan: static security scanner for Dockerfiles and docker-compose files."""

__version__ = "1.0.0"

from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """A single security finding produced by a scanner check."""

    rule_id: str
    severity: str        # "HIGH", "MEDIUM", or "LOW"
    description: str
    detail: str
    fix: str
    service: Optional[str] = None   # populated for compose findings
    line: Optional[int] = None      # 1-based line number, when available
