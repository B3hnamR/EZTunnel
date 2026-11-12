#!/usr/bin/env python3
"""Use matching Zig libc++ and an erratum-aware LLVM final linker."""
import glob
import os
from pathlib import Path
import subprocess
import sys

zig = str(Path(os.environ["EZTUNNEL_ZIG"]).resolve())
arguments = [arg for arg in sys.argv[1:] if arg != "--target=aarch64-unknown-linux-musl"]
if "-Wl,--fix-cortex-a53-843419" in arguments:
    clang = str(Path(os.environ["EZTUNNEL_CLANGXX"]).resolve())
    cache = Path(os.environ["ZIG_GLOBAL_CACHE_DIR"])
    marker = cache / "eztunnel-aarch64-cxx-runtime"
    if not marker.exists():
        source = cache / "eztunnel-aarch64-cxx-runtime.cc"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("int main() { return 0; }\n")
        subprocess.run([zig, "c++", "-target", "aarch64-linux-musl", "-static", str(source), "-o", str(marker)], check=True)
    libraries = []
    for name in ("libc++.a", "libc++abi.a"):
        found = glob.glob(str(cache / "**" / name), recursive=True)
        if len(found) != 1:
            raise RuntimeError("Use a dedicated ARM64 Zig cache; expected one " + name)
        libraries.extend(found)
    arguments = [arg for arg in arguments if arg != "-lstdc++"]
    os.execv(clang, [clang, "--target=aarch64-linux-musl", "-fuse-ld=lld", *arguments,
                      "-Wl,--start-group", *libraries, "-Wl,--end-group"])
os.execv(zig, [zig, "c++", "-target", "aarch64-linux-musl", *arguments])
