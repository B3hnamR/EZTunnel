# Build EZTunnel from source

## Architecture Support

Full-feature static releases are available for Linux x86-64 and ARM64. Read
[architectures.md](architectures.md) for the validated ARM64 cross-toolchain,
native-test scope and ELF differences. Both include browser-compatible TLS and
the six optional transport extensions; `--no-default-features` below is an
explicit user choice, not the ARM64 release configuration. Match packages to
`uname -m`; installers reject the wrong architecture before execution.

In the commands below, replace `VERSION` with the release you downloaded. Releases
are validated with Rust 1.98.1;
the manifest's 1.88 minimum has not been revalidated against every current native
dependency. Cross-compiling musl requires a matching C/C++/header sysroot, not
merely a Rust target installation. Build tools never need application signing keys.

Tested on Ubuntu and Debian. You need `eztunnel-VERSION-source.tar.gz` and the matching `SHA256SUMS`.

## 1. Check the download

Get `SHA256SUMS` from a different place than the source archive, then:

```sh
sha256sum -c SHA256SUMS
```

## 2. Install the tools

```sh
sudo apt update
sudo apt install -y build-essential curl ca-certificates cmake clang
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

`cmake`, `clang` (for the Rust bindings) and the C++ compiler in `build-essential` are needed because the default build includes BoringSSL for the browser-like TLS look (`tls_profile: chrome`). To build without it (no C++ step, about 2 MB smaller, only the `classic` look): `cargo build --locked --release --no-default-features`.

Choose the default option in the Rust installer. Rust 1.88 or newer is required; if Rust is already installed, run `rustup update stable`. The first build needs internet access to download dependencies. Rust's installer page: https://rust-lang.org/tools/install/

## 3. Build

```sh
tar -xzf eztunnel-VERSION-source.tar.gz
cd eztunnel-VERSION
cargo build --locked --release
./target/release/eztunnel --version
```

The program is `target/release/eztunnel`. Optionally run the tests (`cargo test --locked --release --all-targets`; the whole suite takes more than ten minutes, and its timing tests want a machine that is not busy).

Build on Linux; on Windows use WSL.

## 4. Install on this machine

```sh
sudo bash scripts/install.sh --binary target/release/eztunnel
sudo eztunnel
```

## 5. Static build (runs on any x86-64 Linux)

A static binary does not depend on the server's system libraries, so it also runs on older distributions:

```sh
rustup target add x86_64-unknown-linux-musl
export EZTUNNEL_ZIG=/absolute/zig-x86_64-linux-0.17.1/zig
export EZTUNNEL_CLANGXX=/absolute/llvm-22/bin/clang++
export LIBCLANG_PATH=/absolute/llvm-22/lib
# The matching ld.lld must be on PATH, plus cmake.
bash scripts/build-x86_64-musl.sh
```

The static program uses `mimalloc` as its allocator. BoringSSL (the browser-tls feature) is C/C++: since 0.9.13 its C, C++, assembly and bindgen all use Zig's musl headers, and the final link uses Zig's static `libc++`/`libc++abi` through LLVM `lld` (`scripts/cross/x86_64-*`), the same approach as the ARM64 build. The host's glibc `g++`/`libstdc++` and the earlier glibc shim objects are no longer used, and `scripts/build-static.sh` refuses a browser-TLS build without these matching compilers. The result is `target/x86_64-unknown-linux-musl/release/eztunnel`. With `--no-default-features` none of this is needed: `CC_x86_64_unknown_linux_musl=gcc cargo build --locked --release --no-default-features --target x86_64-unknown-linux-musl`.

## 6. Make the installer files

```sh
bash scripts/package-linux.sh target/x86_64-unknown-linux-musl/release/eztunnel dist
cd dist
sha256sum eztunnel-linux-x86_64.run eztunnel-linux-x86_64.tar.gz > SHA256SUMS
```

`dist/` now holds the self-extracting `eztunnel-linux-x86_64.run` and the `.tar.gz`. Run them on a server of the same architecture. Publish `SHA256SUMS` separately from the installer so anyone can verify it, and ship the third-party notices with any redistributed binary.

## Notes

- Never put a private key in the source or in an installer.
- The install location is `/usr/local` and the configuration directory is `/etc/eztunnel` when run as root.
