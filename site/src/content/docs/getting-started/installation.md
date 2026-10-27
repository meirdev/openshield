---
title: Installation
description: "Get the openshield binary from a release or build it from source."
sidebar:
  order: 2
---

## From a release

The release workflow builds a statically linked Linux x86_64 binary. On a matching machine, download the `openshield` asset from [GitHub Releases](https://github.com/meirdev/openshield/releases):

```bash
curl -fL -o openshield https://github.com/meirdev/openshield/releases/latest/download/openshield
chmod +x openshield
./openshield --version
```

You can run the downloaded binary as `./openshield` or put it on your `PATH` to use the commands shown throughout these docs. For repeatable deployments, replace `latest` in the download URL with a specific release tag.

## From source

Building from source requires current stable Rust, a C compiler, and CMake. Use the current toolchain because the workspace uses edition 2024 without declaring a minimum supported Rust version.

```bash
git clone https://github.com/meirdev/openshield.git
cd openshield
cargo build --release --locked
./target/release/openshield --version
```

The build produces `target/release/openshield`, whose runtime dependencies depend on the target you chose. When deploying it, also provide any TLS files, databases, schemas, or challenge pages named in its configuration.

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

Before a deployment or [reload](../../operations/running/#reload), use `--test` to validate configuration, compile active rules, initialize WAF resources, and open log destinations without starting the listener. Upstream connectivity and TLS setup need separate checks.

Continue with [Your first configuration](../first-configuration/) to start a local proxy and test a blocking rule.
