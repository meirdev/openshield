---
title: Running
description: "Validate, start, reload without dropping connections, and debug."
sidebar:
  order: 1
---

## Validate

```bash
openshield --test -c config.yaml
```

Loads the configuration, compiles every rule expression, reads lists, keys, schemas and GeoIP databases, and exits non-zero with the error if anything is wrong. Nothing is bound. Run it in CI and before every reload.

## Start

```bash
openshield -c config.yaml
```

The process stays in the foreground; run it under systemd or another supervisor. It writes `pid_file` and logs to the configured outputs.

## Reload

```bash
kill -HUP "$(cat /tmp/openshield.pid)"
```

`SIGHUP` starts a replacement process with `--upgrade`. The new process loads the configuration, rules, lists, keys, schemas and databases; if that fails, it exits and the old process keeps serving. Otherwise the listening sockets are handed over through `upgrade_sock`, the old process stops accepting, drains its connections and exits. No connection is dropped.

Rate-limit counters start from zero in the new process.

## Debug

The process log goes to stderr and is controlled by `logging.level` or the `RUST_LOG` variable:

```bash
RUST_LOG=openshield=debug,pingora=info openshield -c config.yaml
```

At `debug`, OpenShield logs each rule match, why JWTs were rejected, and why schema operations did not match.

## Exit codes

`0` on a clean stop, `1` when the configuration cannot be loaded or compiled.
