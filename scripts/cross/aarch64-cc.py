#!/usr/bin/env python3
"""Zig musl cross compiler adapter; pass arguments without a shell."""
import os
from pathlib import Path
import sys

zig = str(Path(os.environ["EZTUNNEL_ZIG"]).resolve())
arguments = [arg for arg in sys.argv[1:] if arg != "--target=aarch64-unknown-linux-musl"]
os.execv(zig, [zig, "cc", "-target", "aarch64-linux-musl", *arguments])
