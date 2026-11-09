import pytest

from dockerscan import mcp_server


def test_scan_text_tool():
    out = mcp_server.tool_scan_text("FROM ubuntu:latest\n", "Dockerfile")
    assert out["total"] >= 2 and out["score"] < 100


def test_rule_tools():
    assert len(mcp_server.tool_list_rules()) == 20
    assert mcp_server.tool_get_rule("dc007")["severity"] == "HIGH"
    with pytest.raises(ValueError):
        mcp_server.tool_get_rule("XX999")


def test_server_registers_tools():
    pytest.importorskip("mcp")
    server = mcp_server.build_server()
    assert server is not None
