---
title: Logs
description: "What the access and audit logs contain, in JSON and in text."
sidebar:
  order: 2
---

The two logs share a `request_id`, so an audit record can be traced to its access line. Settings are under [Logging](../../configuration/logging/).

## Access log

The host writes an access-log entry after each response, recording the request, HTTP outcome, and WAF decision:

```json
{"request_id":"1ae4c898-…","timestamp":"2026-10-25T09:44:33.326Z","client_ip":"127.0.0.1","method":"GET","protocol":"HTTP/1.1","host":"127.0.0.1:8080","path":"/search","query":"q=1'%20OR%20'1'='1","status":403,"duration_ms":0.412,"bytes_received":0,"bytes_sent":18,"waf_action":"block","waf_matched_rules":["sqli-args","block-injection"]}
```

The `waf_action` field records the most recent terminal decision as `pass`, `allow`, `block`, or `challenge`. It can differ from the HTTP outcome—for example, detection-only mode can record `block` alongside an upstream `200`—so read `status` for the response actually sent. The text format shows the same distinction:

```text
2026-10-25T09:44:33.326Z [1ae4c898-…] 127.0.0.1 GET /search?q=… -> 403 0.412ms waf=block
```

Under nginx there is no separate access log: the same values are nginx [variables](../../hosts/nginx-module/#variables) for `log_format`.

## Audit log

The WAF writes an audit record when at least one logging-enabled rule matches, collecting the request's matches and supporting data into a single entry:

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

With `log_payloads: true`, the `waf_payloads` map includes fields captured from logging-enabled matches and is omitted when empty. This setting does not control the rest of the record: headers are still stored as `[name, value]` pairs that preserve repeated names.

Captured bodies contain the retained buffer decoded as text. The proxy can capture request bodies without body rules, while response-body capture requires `inspect_response_body: true`. The `response` object itself appears when the host supplies response headers.

Body-size fields measure data seen by the core, which may be less than the full transfer if inspection ends early. An uninspected response body may therefore report zero; see [Body sizes and truncation](../../configuration/body-inspection/#body-sizes-and-truncation).

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

Text output limits body excerpts to 500 bytes; JSON includes the captured buffer. File writes use a lock to prevent cooperating OpenShield processes from interleaving records.

## Shipping logs elsewhere

Choose JSON when your collector expects one record per line, or configure multiline collection for text audit records. If you are embedding the core, you can also provide a custom destination through its `AuditSink` trait.
