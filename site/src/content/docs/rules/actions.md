---
title: Actions
description: "Block, allow, log, score, challenge and execute, with their parameters."
sidebar:
  order: 3
---

| Action | Effect |
| --- | --- |
| `block` | Stop the request and send a response; `403` with an empty body by default |
| `allow` | Skip the remaining rules of the current phase |
| `log` | Record the match in the audit log and continue |
| `score` | Add to [scores](../scores/) and continue |
| `challenge` | Require a [Turnstile verification](../../protections/turnstile-challenges/) before forwarding |
| `execute` | Run a custom or managed [ruleset](../rulesets/#executing-a-ruleset) |

Which actions take effect depends on the [phase](../phases/). With `detection_only: true`, `block` and `challenge` are logged but not enforced.

## The block response

```yaml
- id: block-admin
  action: block
  expression: 'http.request.uri.path == "/admin"'
  action_parameters:
    response:
      status_code: 404
      content_type: text/plain
      content: "not found"
```

Any status is allowed. In `response_body`, only `content` is used, since the status and headers are already sent.

## Scores

```yaml
- id: sqli-args
  action: score
  expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
  action_parameters:
    scores:
      - name: sqli
        increment: 10
```

Each `name` must be declared in the top-level `scores` list. `increment` defaults to `1` and may be negative.

## Allow

`allow` ends the current phase for this request: later rules in the phase do not run, later phases still do. It is the way to exempt trusted clients from the detection rules that follow:

```yaml
- id: trusted
  action: allow
  expression: "ip.src in $office"
- id: run-detections
  action: execute
  expression: "true"
  action_parameters: {id: detections}
```

## Logging

Every match is written to the audit log unless the rule says `logging: {enabled: false}`. Blocks and challenges are logged either way in the access log's `waf_action`.
