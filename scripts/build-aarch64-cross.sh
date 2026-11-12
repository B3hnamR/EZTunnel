#!/usr/bin/env bash
# Full-feature cross-build, using explicitly provisioned public toolchains.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
: "${EZTUNNEL_ZIG:?Set absolute path to Zig 0.17.1}"
: "${EZTUNNEL_CLANGXX:?Set absolute path to clang++-22 with lld on PATH}"
: "${LIBCLANG_PATH:?Set path to LLVM22 libclang for bindgen}"
zig_root=$(dirname "$EZTUNNEL_ZIG")
export ZIG_GLOBAL_CACHE_DIR=${ZIG_GLOBAL_CACHE_DIR:-$root/target/zig-aarch64-global}
export ZIG_LOCAL_CACHE_DIR=${ZIG_LOCAL_CACHE_DIR:-$root/target/zig-aarch64-local}
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"
for wrapper in scripts/cross/aarch64-cc.py scripts/cross/aarch64-cxx.py scripts/cross/aarch64-ar.py; do
    [[ -x $wrapper ]] || { echo "Make $wrapper executable before using the read-only build tree." >&2; exit 1; }
done
export CC_aarch64_unknown_linux_musl=$root/scripts/cross/aarch64-cc.py
export CXX_aarch64_unknown_linux_musl=$root/scripts/cross/aarch64-cxx.py
export AR_aarch64_unknown_linux_musl=$root/scripts/cross/aarch64-ar.py
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$CXX_aarch64_unknown_linux_musl
export CMAKE_TOOLCHAIN_FILE_aarch64_unknown_linux_musl=$root/scripts/cross/aarch64-toolchain.cmake
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_musl="--target=aarch64-linux-musl -nostdinc -isystem $zig_root/lib/include -isystem $zig_root/lib/libc/include/aarch64-linux-musl -isystem $zig_root/lib/libc/include/generic-musl -isystem $zig_root/lib/libc/include/aarch64-linux-any -isystem $zig_root/lib/libc/include/any-linux-any"
export EZTUNNEL_TARGET=aarch64-unknown-linux-musl
exec bash scripts/build-static.sh "$@"
