"""
File-type detection and the scanning entry points shared by the CLI,
the AI layer and the MCP server.
"""

import os
import shutil
import tempfile

from . import Finding
from .compose_scanner import scan_compose
from .dockerfile_scanner import scan_dockerfile

# Directories that never contain project Docker artifacts worth scanning.
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
}

# Extensions that can hold a compose file; anything else is only sniffed when
# it has no extension (e.g. a plain `Dockerfile`).
_SNIFF_EXTENSIONS = {"", ".yml", ".yaml"}


def detect_type(path: str) -> str:
    """Return 'compose', 'dockerfile', or 'unknown'."""
    name = os.path.basename(path).lower()

    if "docker-compose" in name or name in ("compose.yml", "compose.yaml"):
        return "compose"
    if "dockerfile" in name:
        return "dockerfile"

    if os.path.splitext(name)[1] not in _SNIFF_EXTENSIONS:
        return "unknown"

    # Peek at the first 1 KB of content as a fallback heuristic.
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            head = fh.read(1024)
        if "services:" in head and ("image:" in head or "build:" in head):
            return "compose"
        if head.lstrip().startswith("FROM ") or "\nFROM " in head:
            return "dockerfile"
    except OSError:
        pass

    return "unknown"


def collect_targets(directory: str) -> list[str]:
    """Walk *directory* and return every file that looks like a Docker artifact."""
    targets: list[str] = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            full = os.path.join(root, fname)
            if detect_type(full) != "unknown":
                targets.append(full)
    return sorted(targets)


def scan_file(path: str) -> list[Finding]:
    """
    Scan *path* with the scanner matching its type.

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError: if the type is unknown or the content is invalid.
    """
    file_type = detect_type(path)
    if file_type == "compose":
        return scan_compose(path)
    if file_type == "dockerfile":
        return scan_dockerfile(path)
    raise ValueError(f"Cannot determine file type for '{path}'.")


def scan_text(content: str, filename: str, context_dir: str | None = None) -> list[Finding]:
    """
    Scan in-memory *content* as if it were saved under *filename*.

    *context_dir* is the directory the real file lives in: its `.dockerignore`
    is mirrored so DF005 gives the same answer as a scan of the real file.
    """
    filename = os.path.basename(filename)
    with tempfile.TemporaryDirectory(prefix="dockerscan-") as tmp:
        if context_dir:
            ignore = os.path.join(context_dir, ".dockerignore")
            if os.path.isfile(ignore):
                shutil.copy(ignore, os.path.join(tmp, ".dockerignore"))
        path = os.path.join(tmp, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return scan_file(path)
