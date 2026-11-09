#!/usr/bin/env python3
"""Render the real output of a dockerscan run as docs/demo.svg (no external tools)."""

import html
import os
import pty
import re
import subprocess
import sys

COMMAND = ["dockerscan", "--file", "tests/samples/docker-compose.insecure.yml", "--severity", "HIGH"]
COLORS = {"31": "#ff6b6b", "91": "#ff6b6b", "33": "#f5d76e", "93": "#f5d76e",
          "36": "#6bd6ff", "96": "#6bd6ff", "32": "#7ee787", "92": "#7ee787"}
FG, BG, LH, CHAR_W = "#d4d4d4", "#1e1e1e", 20, 7.9
# Emoji glyphs are missing from many SVG renderers and break text alignment.
EMOJI = re.compile("[\U0001F000-\U0001FFFF\u2600-\u27BF\uFE0F]")


def run() -> str:
    master, slave = pty.openpty()
    proc = subprocess.Popen(COMMAND, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    out = b""
    while True:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    proc.wait()
    return EMOJI.sub("", out.decode("utf-8", "replace").replace("\r", ""))


def to_tspans(line: str) -> str:
    parts, color = [], None
    for tok in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", tok)
        if m:
            codes = [c for c in m.group(1).split(";") if c]
            color = None if not codes or codes == ["0"] else COLORS.get(codes[-1], color)
        elif tok:
            fill = f' fill="{color}"' if color else ""
            parts.append(f'<tspan{fill}>{html.escape(tok)}</tspan>')
    return "".join(parts)


def main() -> None:
    lines = ["$ " + " ".join(COMMAND)] + run().rstrip().split("\n")
    height = 56 + LH * len(lines)
    visible = max(len(re.sub(r"\x1b\[[0-9;]*m", "", ln)) for ln in lines)
    W = int(visible * CHAR_W) + 40
    rows = []
    for i, line in enumerate(lines):
        y = 48 + LH * i
        body = html.escape(line) if i == 0 else to_tspans(line)
        style = ' fill="#7ee787"' if i == 0 else ""
        rows.append(f'<text x="20" y="{y}" xml:space="preserve"{style}>{body}</text>')
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{height}" '
        f'viewBox="0 0 {W} {height}" font-family="ui-monospace,Menlo,Consolas,monospace" '
        f'font-size="13" fill="{FG}">'
        f'<rect width="{W}" height="{height}" rx="10" fill="{BG}"/>'
        '<circle cx="22" cy="18" r="6" fill="#ff5f56"/><circle cx="42" cy="18" r="6" fill="#ffbd2e"/>'
        '<circle cx="62" cy="18" r="6" fill="#27c93f"/>' + "".join(rows) + "</svg>"
    )
    with open("docs/demo.svg", "w", encoding="utf-8") as fh:
        fh.write(svg)
    print(f"wrote docs/demo.svg ({len(lines)} lines)", file=sys.stderr)


if __name__ == "__main__":
    main()
