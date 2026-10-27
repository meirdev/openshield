---
title: Logging
description: "The access log, the audit log, payload capture and detection-only mode."
sidebar:
  order: 4
---

The **access log** records the HTTP outcome for each request and belongs to the host. The **audit log** records requests with at least one logging-enabled rule match and is written by the WAF, with the same format under the proxy and nginx.

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
| `log_payloads` | `false` | Add `waf_payloads` with the field values referenced by logging-enabled matching rules |
| `detection_only` | `false` | Record rule decisions without enforcing their block or challenge outcomes |

What the records contain, and the text formats, are described under [Logs](../../operations/logs/).

## Per rule

Setting a rule's `logging: {enabled: false}` omits its ID from the audit record and the access log's matched-rule list without changing its action. If no logging-enabled rule matches, the request produces no audit record, although its access log can still report `waf_action: block` or `challenge`. This setting does not control process logging.

## Detection-only mode

With `detection_only: true`, OpenShield records rule decisions without enforcing their blocking or challenge actions. A request can therefore have a logged `block` decision while receiving `200` from the upstream.

Evaluation otherwise follows its normal order: terminal matches stop the phase, and scores and rate-limit counters still change. If you want evaluation to continue after a match, use `action: log`. Body-limit rejection and host limits apply separately, as described in [Body inspection](../body-inspection/).

## Captured data

Setting `log_payloads: false` removes the extra `waf_payloads` map, but does not redact the rest of the audit record. Headers, cookies, query strings, and captured bodies can still appear, including request bodies captured by the proxy without body rules. The [audit log reference](../../operations/logs/#audit-log) explains what is retained.

## Rotation

Log files are opened once and appended to. `logrotate` with `copytruncate` works; a rename-based rotation needs a restart or a [reload](../../operations/running/#reload) to reopen the files.
