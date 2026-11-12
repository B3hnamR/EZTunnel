#!/usr/bin/env python3
"""Zig musl C compiler adapter for x86-64; pass arguments without a shell."""
import os
from pathlib import Path
import sys

zig = str(Path(os.environ["EZTUNNEL_ZIG"]).resolve())
arguments = [arg for arg in sys.argv[1:] if arg != "--target=x86_64-unknown-linux-musl"]
os.execv(zig, [zig, "cc", "-target", "x86_64-linux-musl", *arguments])
