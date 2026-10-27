---
title: Logs
description: "What the access and audit logs contain, in JSON and in text."
sidebar:
  order: 2
---

The two logs share a `request_id`, so an audit record can be traced to its access line. Settings are under [Logging](../../configuration/logging/).

## Access log

One entry per request, written by the host after the response:

```json
{"request_id":"1ae4c898-…","timestamp":"2026-10-25T09:44:33.326Z","client_ip":"127.0.0.1","method":"GET","protocol":"HTTP/1.1","host":"127.0.0.1:8080","path":"/search","query":"q=1'%20OR%20'1'='1","status":403,"duration_ms":0.412,"bytes_received":0,"bytes_sent":18,"waf_action":"block","waf_matched_rules":["sqli-args","block-injection"]}
```

`waf_action` is `pass`, `allow`, `block` or `challenge`. In text format:

```text
2026-10-25T09:44:33.326Z [1ae4c898-…] 127.0.0.1 GET /search?q=… -> 403 0.412ms waf=block
```

Under nginx there is no separate access log: the same values are nginx [variables](../../hosts/nginx-module/#variables) for `log_format`.

## Audit log

One record per request on which at least one rule matched with logging enabled, written by the WAF:

```json
{
  "request_id": "1ae4c898-…",
  "timestamp": "2026-10-25T09:44:33.326Z",
  "waf_action": "block",
  "waf_matched_rules": [{"id": "sqli-args", "action": "score"}, {"id": "block-injection", "action": "block"}],
  "waf_scores": {"sqli": 10},
  "waf_payloads": {"http.request.uri.args.values": ["1' OR '1'='1"], "score.sqli": 10},
  "request": {
    "client_ip": "127.0.0.1", "method": "GET", "protocol": "HTTP/1.1", "host": "127.0.0.1:8080",
    "path": "/search", "query": "q=1'%20OR%20'1'='1",
    "headers": [["host", "127.0.0.1:8080"], ["user-agent", "curl/8.18.0"]],
    "body": null, "body_size": 0
  },
  "response": {"status": 403, "headers": [["content-type", "text/plain"]], "body_size": 18}
}
```

- `waf_payloads` is present with `log_payloads: true` and holds the values of the fields the matching rules referenced.
- Headers are lists of `[name, value]` pairs in wire order, so repeated headers are kept.
- Bodies are included when they were inspected; `response` is present when a response was sent.

The text format puts a summary on one line and details below it, request lines marked `>` and response lines `<`:

```text
2026-10-25T09:44:33.326Z [1ae4c898-…] block 127.0.0.1 127.0.0.1:8080 "GET /search?q=… HTTP/1.1" -> 403
  rules: sqli-args:score, block-injection:block
  scores: sqli=10
  payload http.request.uri.args.values: ["1' OR '1'='1"]
  > host: 127.0.0.1:8080
  > user-agent: curl/8.18.0
  < content-type: text/plain
```

Bodies are shown up to 500 bytes. Several processes may append to the same file: each record is written in one call under a file lock, so records never interleave.

## Shipping logs elsewhere

Both logs are line-oriented and append-only, which suits any collector that tails files or reads stdout. In code, the audit log accepts additional sinks through the `AuditSink` trait of `openshield-core`.
