#!/usr/bin/env bash
# Full-feature static x86-64 build with one consistent musl C/C++ toolchain (Zig musl
# headers + libc++/libc++abi, LLVM lld final link). No glibc libstdc++ or shim objects.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
: "${EZTUNNEL_ZIG:?Set absolute path to Zig 0.17.1}"
: "${EZTUNNEL_CLANGXX:?Set absolute path to clang++-22 with lld on PATH}"
: "${LIBCLANG_PATH:?Set path to LLVM22 libclang for bindgen}"
zig_root=$(dirname "$EZTUNNEL_ZIG")
export ZIG_GLOBAL_CACHE_DIR=${ZIG_GLOBAL_CACHE_DIR:-$root/target/zig-x86_64-global}
export ZIG_LOCAL_CACHE_DIR=${ZIG_LOCAL_CACHE_DIR:-$root/target/zig-x86_64-local}
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"
for wrapper in scripts/cross/x86_64-cc.py scripts/cross/x86_64-cxx.py scripts/cross/x86_64-ar.py; do
    [[ -x $wrapper ]] || { echo "Make $wrapper executable before using the read-only build tree." >&2; exit 1; }
done
export CC_x86_64_unknown_linux_musl=$root/scripts/cross/x86_64-cc.py
export CXX_x86_64_unknown_linux_musl=$root/scripts/cross/x86_64-cxx.py
export AR_x86_64_unknown_linux_musl=$root/scripts/cross/x86_64-ar.py
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$CXX_x86_64_unknown_linux_musl
export CMAKE_TOOLCHAIN_FILE_x86_64_unknown_linux_musl=$root/scripts/cross/x86_64-toolchain.cmake
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_linux_musl="--target=x86_64-linux-musl -nostdinc -isystem $zig_root/lib/include -isystem $zig_root/lib/libc/include/x86_64-linux-musl -isystem $zig_root/lib/libc/include/generic-musl -isystem $zig_root/lib/libc/include/x86-linux-any -isystem $zig_root/lib/libc/include/any-linux-any"
export EZTUNNEL_TARGET=x86_64-unknown-linux-musl
exec bash scripts/build-static.sh "$@"
