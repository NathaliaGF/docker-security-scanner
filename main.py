#!/usr/bin/env python3
"""Backwards-compatible entry point: `python main.py` == `dockerscan`."""

import sys

from dockerscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
