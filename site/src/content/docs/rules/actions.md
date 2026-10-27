---
title: Actions
description: "Block, allow, log, score, challenge and execute, with their parameters."
sidebar:
  order: 3
---

A rule's action determines what happens when its expression matches. The available actions are:

| Action | Effect |
| --- | --- |
| `block` | Stop the request and send a response; `403` with an empty body by default |
| `allow` | Skip the remaining rules of the current phase |
| `log` | Record the match in the audit log and continue |
| `score` | Add to [scores](../scores/) and continue |
| `challenge` | Require a [Turnstile verification](../../protections/turnstile-challenges/) before forwarding |
| `execute` | Run a custom or managed [ruleset](../rulesets/#executing-a-ruleset) |

When `block`, `allow`, or `challenge` matches, evaluation of the current phase ends. The `log` and `score` actions let it continue. This ordering also applies in detection-only mode, while the action's effect depends on the [phase](../phases/). Place the examples below under a root ruleset's `rules:`.

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

Use a valid HTTP status code in a request phase. In `response_body`, only `content` is used: the client has already received the status and headers. A response-body block without `content` suppresses the remaining body.

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

`allow` ends the current phase; it does not exempt the request from later phases. The following fragment skips subsequent header-phase detections for clients in an `office` list. It assumes that list and a `detections` ruleset are configured:

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

OpenShield collects logging-enabled matches into one audit record per request. Rules skipped during evaluation are absent, and rate-limited rules appear only when their limit is exceeded. Setting `logging: {enabled: false}` removes a rule from that record, but its terminal decision can still appear in `waf_action`; see [Logs](../../operations/logs/).
