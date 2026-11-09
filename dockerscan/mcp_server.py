"""
MCP server: lets any MCP-capable AI assistant call the scanner as a tool.

Run with `dockerscan-mcp` (stdio). Requires the extra: pip install 'dockerscan[mcp]'.
The assistant gets deterministic findings to reason over instead of guessing
security issues from raw text.
"""

from dataclasses import asdict

from .core import scan_file, scan_text
from .references import cis_reference
from .report import compute_score
from .rules import COMPOSE_RULES, DOCKERFILE_RULES

_ALL_RULES = {**COMPOSE_RULES, **DOCKERFILE_RULES}


def _payload(findings) -> dict:
    return {
        "score": compute_score(findings),
        "total": len(findings),
        "findings": [
            {**asdict(f), "reference": cis_reference(f.rule_id)} for f in findings
        ],
    }


def tool_scan_file(path: str) -> dict:
    """Scan a Dockerfile or docker-compose file on disk."""
    return _payload(scan_file(path))


def tool_scan_text(content: str, filename: str = "Dockerfile") -> dict:
    """Scan pasted content. *filename* decides the type (Dockerfile or docker-compose.yml)."""
    return _payload(scan_text(content, filename))


def tool_list_rules() -> list[dict]:
    """List every rule with id, severity and description."""
    return [
        {"id": r.id, "severity": r.severity, "description": r.description,
         "reference": cis_reference(r.id)}
        for r in sorted(_ALL_RULES.values(), key=lambda r: r.id)
    ]


def tool_get_rule(rule_id: str) -> dict:
    """Return the full explanation and recommended fix of one rule."""
    rule = _ALL_RULES.get(rule_id.upper())
    if rule is None:
        raise ValueError(f"Unknown rule '{rule_id}'. Use list_rules.")
    return {**asdict(rule), "reference": cis_reference(rule.id)}


def build_server():
    try:
        from mcp.server.mcpserver import MCPServer as Server  # mcp >= 2
    except ImportError:
        try:
            from mcp.server.fastmcp import FastMCP as Server  # mcp 1.x
        except ImportError as exc:
            raise SystemExit("Install the MCP extra: pip install 'dockerscan[mcp]'") from exc

    server = Server("dockerscan")
    server.tool(name="scan_file")(tool_scan_file)
    server.tool(name="scan_text")(tool_scan_text)
    server.tool(name="list_rules")(tool_list_rules)
    server.tool(name="get_rule")(tool_get_rule)
    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
