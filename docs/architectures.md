# Linux Architectures

EZTunnel ships full-feature static Linux executables for **x86-64**
(`x86_64-unknown-linux-musl`) and **ARM64** (`aarch64-unknown-linux-musl`).
They use the same source, protocol, configuration and six optional transport
extensions. Browser-compatible TLS, BoringSSL, allocator and crypto are not
disabled on ARM64. No emulation is required on the destination host.

The validated x86-64 release is static PIE. The current Rust musl ARM64 target
produces a fixed-address static ELF (ET_EXEC), not PIE; the release report states
this difference explicitly. Both have no dynamic loader, no executable stack
and no writable/executable load segment. No cryptographic/session protection or
Cortex-A53 linker workaround was disabled. Adding ARM static PIE requires a
separate supported CRT/link strategy rather than merely changing an ELF flag.

Select the file matching `uname -m`. `x86_64`/`amd64` means x86-64;
`aarch64`/`arm64` means ARM64. The installer checks the ELF architecture before
executing or installing it. The updater also checks architecture, ELF class and
byte order; an ARM64 executable cannot replace an x86-64 installation or vice
versa. These checks are distinct from official-update signature verification.

## Ordinary Builds

`cargo build --locked --release` builds for the installed native Rust toolchain.
For static Linux use `scripts/build-x86_64-musl.sh` or
`scripts/build-aarch64-cross.sh`; both call `scripts/build-static.sh` with one
consistent musl C/C++ toolchain. Install the matching Rust musl target first.
Native/cross musl C, C++ and assembly compilers, CMake and libclang are needed for
the full default browser-TLS build. Do not use host glibc headers for ARM musl
bindgen or accidentally link host C++ libraries.

## Validated ARM64 Cross Toolchain

The release was built offline on x86-64 using Rust1.98.1, its official ARM64 musl
standard library, Zig0.17.1 C/C++/libc++ sysroot, and LLVM22.1.8 final linker and
libclang. `scripts/build-aarch64-cross.sh` and `scripts/cross/` record the necessary
target, header and CMake configuration. Provision tools separately; build scripts
do not download/install software or execute upstream installer scripts.

```sh
export EZTUNNEL_ZIG=/absolute/zig-x86_64-linux-0.17.1/zig
export EZTUNNEL_CLANGXX=/absolute/llvm-22/bin/clang++
export LIBCLANG_PATH=/absolute/llvm-22/lib
# Ensure the matching ld.lld is on PATH and Rust ARM64 musl std is installed.
bash scripts/build-aarch64-cross.sh
bash scripts/package-linux.sh target/aarch64-unknown-linux-musl/release/eztunnel dist-arm64
```

Use a dedicated Zig cache for this target. C/C++ code uses Zig's musl headers and
static libc++/libc++abi; the final Rust link uses LLVM lld so the required
`--fix-cortex-a53-843419` workaround remains enabled. No erratum or security flag
was removed to make the build pass. The package script reads the binary's ELF
machine instead of naming it after the build host, and never executes a foreign
binary while packaging. Runtime license notices are added to each release archive.

## Native And Mixed Validation

Both architectures pass the same 490-test browser-enabled inventory natively.
ARM64 validation used private namespaces on an ARM64 host, not QEMU. Kernel/raw/
TUN/Mirage, browser TLS, direct datagrams, migration, hopping, packet fallback,
CLI/PTY, wrong-architecture installation and lifecycle tests are included.
The release report distinguishes direct-WAN mixed-architecture checks from opaque
SSH loopback relays used where inbound test ports were unreachable. No firewall
or production installation was changed to make tests pass.

ARM and x86 performance measurements use different hosts and cannot isolate CPU
architecture as the cause of speed differences. See the versioned validation
report for exact workloads, binaries, toolchain hashes and limitations.

The known0.9.1 gaming-option risks remain: opt-in adaptive control can develop
long-run queueing, direct-channel renewal/rebinding can lose UDP, and TCP packet
fallback can have high tail latency. ARM support does not claim to fix those
algorithm/network risks. Ordinary defaults remain unchanged.
