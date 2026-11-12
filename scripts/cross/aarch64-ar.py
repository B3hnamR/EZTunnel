#!/usr/bin/env python3
import os
from pathlib import Path
import sys

zig = str(Path(os.environ["EZTUNNEL_ZIG"]).resolve())
os.execv(zig, [zig, "ar", *sys.argv[1:]])
