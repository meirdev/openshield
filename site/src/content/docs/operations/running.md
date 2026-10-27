---
title: Running
description: "Validate configuration, start the proxy, reload, and inspect process logs."
sidebar:
  order: 1
---

## Validate

```bash
openshield --test -c config.yaml
```

Run this command with the service's working directory and permissions so file resolution and access checks match production. It loads the configuration, compiles active rules, initializes WAF resources, and opens log destinations before exiting without binding a listener.

The check does not test upstream connectivity or load the listener's TLS certificate and key. Verify those separately when changing them.

## Start

```bash
openshield -c config.yaml
```

The process stays in the foreground; run it under systemd or another supervisor. It writes `pid_file` and logs to the configured outputs.

## Reload

```bash
openshield --test -c config.yaml && kill -HUP "$(cat /tmp/openshield.pid)"
```

Use the running service's configuration path and `pid_file` in this command. After validation succeeds, `SIGHUP` spawns a replacement with `--upgrade` and signals the old process to transfer listening sockets through `upgrade_sock` before draining its connections.

**There is no readiness check before the old process is signaled**, so a failed replacement is not guaranteed to leave the old process serving. Validate first, keep listener and upgrade-socket settings consistent across the handoff, and check startup logs to confirm that the new process accepts requests.

Because the replacement is a new process, its rate-limit counters start from zero. This procedure applies to the standalone proxy; the nginx module uses `nginx -t` followed by `nginx -s reload`.

## Debug

The process log goes to stderr and is controlled by `logging.level` or the `RUST_LOG` variable:

```bash
RUST_LOG=openshield=debug,pingora=info openshield -c config.yaml
```

At `debug`, OpenShield logs each rule match, why JWTs were rejected, and why schema operations did not match.

## Exit codes

Configuration and WAF initialization failures exit with `1`. Other startup failures, such as an invalid upstream port or unreadable TLS files, can exit differently. Treat any non-zero exit as a failure and check stderr.
