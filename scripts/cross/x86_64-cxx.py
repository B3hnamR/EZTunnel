#!/usr/bin/env python3
"""Zig musl C++ for x86-64, with matching static libc++/libc++abi for the final link.

BoringSSL's C++ is compiled against Zig's musl headers and libc++, so the final Rust link
must use the same runtime. That link (recognised by Rust's -nodefaultlibs) goes through
clang++ with lld and Zig's libc++.a/libc++abi.a; host glibc libstdc++ is never linked.
"""
import glob
import os
from pathlib import Path
import subprocess
import sys

zig = str(Path(os.environ["EZTUNNEL_ZIG"]).resolve())
arguments = [arg for arg in sys.argv[1:] if arg != "--target=x86_64-unknown-linux-musl"]
if "-nodefaultlibs" in arguments:
    clang = str(Path(os.environ["EZTUNNEL_CLANGXX"]).resolve())
    cache = Path(os.environ["ZIG_GLOBAL_CACHE_DIR"])
    marker = cache / "eztunnel-x86_64-cxx-runtime"
    if not marker.exists():
        source = cache / "eztunnel-x86_64-cxx-runtime.cc"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("int main() { return 0; }\n")
        subprocess.run([zig, "c++", "-target", "x86_64-linux-musl", "-static", str(source), "-o", str(marker)], check=True)
    libraries = []
    for name in ("libc++.a", "libc++abi.a"):
        found = glob.glob(str(cache / "**" / name), recursive=True)
        if len(found) != 1:
            raise RuntimeError("Use a dedicated x86-64 Zig cache; expected one " + name)
        libraries.extend(found)
    arguments = [arg for arg in arguments if arg != "-lstdc++"]
    os.execv(clang, [clang, "--target=x86_64-linux-musl", "-fuse-ld=lld", *arguments,
                     "-Wl,--start-group", *libraries, "-Wl,--end-group"])
os.execv(zig, [zig, "c++", "-target", "x86_64-linux-musl", *arguments])
