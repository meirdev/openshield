---
title: Logging
description: "The access log, the audit log, payload capture and detection-only mode."
sidebar:
  order: 4
---

Two logs are written. The **access log** has one line per request and belongs to the host. The **audit log** has one record per request on which rules matched, and is written by the WAF itself, so it looks the same under the proxy and under nginx.

```yaml
logging:            # the proxy's
  level: info       # process log level; RUST_LOG overrides it
  format: json      # json or text
  access_log: /dev/stdout
audit_log:          # the WAF's
  path: /dev/stderr
  format: json      # json or text
log_payloads: false
detection_only: false
```

| Setting | Default | Description |
| --- | --- | --- |
| `logging.level` | `info` | Level of the process log: `debug`, `info`, `warn`, `error`. `debug` explains why tokens and schemas reject requests |
| `logging.format` | `json` | Access log format |
| `logging.access_log` | `/dev/stdout` | `/dev/stdout`, `/dev/stderr` or a file that is appended to |
| `audit_log.path` | `/dev/stderr` | Same choices. Several processes may share one file: each record is written under a file lock |
| `audit_log.format` | `json` | Audit log format |
| `log_payloads` | `false` | Include, in each audit record, the values of the fields the matching rules referenced |
| `detection_only` | `false` | Evaluate and log, but never block or challenge |

What the records contain, and the text formats, are described under [Logs](../../operations/logs/).

## Per rule

A rule's `logging: {enabled: false}` keeps its action but leaves it out of the audit log and of the access log's matched-rule list, for rules that fire constantly and tell you nothing.

## Rotation

Log files are opened once and appended to. `logrotate` with `copytruncate` works; a rename-based rotation needs a restart or a [reload](../../operations/running/#reload) to reopen the files.
