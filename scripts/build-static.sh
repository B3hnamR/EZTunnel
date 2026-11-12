#!/usr/bin/env bash
# Static Linux build for x86_64 or aarch64. See docs/build-from-source.md.
# Extra arguments go to cargo (for example --no-default-features, which needs none of the C++ workarounds).
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$ROOT"
case "${EZTUNNEL_TARGET:-$(uname -m)}" in
    x86_64|amd64|x86_64-unknown-linux-musl) target=x86_64-unknown-linux-musl ;;
    aarch64|arm64|aarch64-unknown-linux-musl) target=aarch64-unknown-linux-musl ;;
    *) echo 'Supported targets: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl' >&2; exit 2 ;;
esac
build_dir=${CARGO_TARGET_DIR:-$ROOT/target}
mkdir -p "$build_dir"
# BoringSSL (the default browser-tls feature) is C/C++. Its C, C++, assembly and bindgen must
# share one musl target sysroot and the final link must use the matching libc++/libc++abi;
# host glibc g++/libstdc++ and shim objects are never used. scripts/build-x86_64-musl.sh and
# scripts/build-aarch64-cross.sh set this up. Without BoringSSL (--no-default-features) no
# C++ toolchain is needed.
no_boringssl=0
for arg in "$@"; do
    [ "$arg" = "--no-default-features" ] && no_boringssl=1
done
if [ "$no_boringssl" = 0 ]; then
    if [ "$target" = x86_64-unknown-linux-musl ]; then
        : "${CC_x86_64_unknown_linux_musl:?Use scripts/build-x86_64-musl.sh (matching musl C compiler)}"
        : "${CXX_x86_64_unknown_linux_musl:?Use scripts/build-x86_64-musl.sh (matching musl C++ compiler)}"
        : "${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:?Use scripts/build-x86_64-musl.sh (matching static linker)}"
        export CFLAGS="${CFLAGS:-} -ffile-prefix-map=$ROOT=/_/app -ffile-prefix-map=${CARGO_HOME:-$HOME/.cargo}=/_/deps"
        export CXXFLAGS="${CXXFLAGS:-} -ffile-prefix-map=$ROOT=/_/app -ffile-prefix-map=${CARGO_HOME:-$HOME/.cargo}=/_/deps"
    else
        # Cross C/C++/ASM and bindgen must share a target sysroot. Never use
        # host g++/headers by accident, or silently omit browser-compatible TLS.
        : "${CC_aarch64_unknown_linux_musl:?Set the aarch64 musl C compiler}"
        : "${CXX_aarch64_unknown_linux_musl:?Set the matching aarch64 musl C++ compiler}"
        : "${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:?Set the aarch64 static linker}"
    fi
fi
# The default profile is `release`; `--profile <name>` (for example `--profile dist`, the
# optimized distribution build) selects another and is not combined with `--release`.
profile=release
output_dir=$build_dir
previous=""
for argument in "$@"; do
    [ "$previous" = "--profile" ] && profile="$argument"
    [ "$previous" = "--target-dir" ] && output_dir="$argument"
    case "$argument" in --profile=*) profile="${argument#--profile=}";; esac
    case "$argument" in --target-dir=*) output_dir="${argument#--target-dir=}";; esac
    previous="$argument"
done
if [ "$profile" = release ] && [[ " $* " != *" --profile"* ]]; then
    cargo build --locked --release --target "$target" "$@"
else
    cargo build --locked --target "$target" "$@"
fi
echo "$output_dir/$target/$profile/eztunnel"
