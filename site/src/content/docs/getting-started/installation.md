---
title: Installation
description: "Get the openshield binary from a release or build it from source."
sidebar:
  order: 2
---

## From a release

Releases on [GitHub](https://github.com/meirdev/openshield/releases) ship `openshield`, a statically linked binary for Linux x86_64 that runs on any distribution:

```bash
curl -L -o openshield https://github.com/meirdev/openshield/releases/latest/download/openshield
chmod +x openshield
./openshield --version
```

## From source

You need a Rust toolchain that supports edition 2024 (Rust 1.85 or newer, [rustup](https://rustup.rs) installs it):

```bash
git clone https://github.com/meirdev/openshield.git
cd openshield
cargo build --release
./target/release/openshield --version
```

The binary is `target/release/openshield`. It has no runtime dependencies beyond the files your configuration names: an optional TLS certificate, GeoIP databases, OpenAPI documents.

## The nginx module

The nginx module is built against the nginx it will load into, so it is not part of the release. See [nginx module](../../hosts/nginx-module/#building).

## Command line

```text
openshield [OPTIONS]

  -c, --config <FILE>   Configuration file (default: config.yaml)
  -t, --test            Validate the configuration and exit
  -u, --upgrade         Take over listening sockets from a running instance
  -h, --help
  -V, --version
```

`--test` loads the configuration, compiles every rule expression, reads keys, schemas and lists, and exits with a non-zero status on any error. Run it before every deploy and reload.
