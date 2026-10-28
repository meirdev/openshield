---
title: Body inspection
description: "Body buffering, partial inspection, and oversized-body handling."
sidebar:
  order: 3
---

When a configuration contains active `request_body` rules, OpenShield holds request data until those rules can evaluate it. Without them, the proxy streams the body while retaining a capped copy for fields and audit logging. To hold and enforce rules on response bodies as well, enable `inspect_response_body` and add `response_body` rules.

| Setting                      | Default           | Purpose                                     |
| ---------------------------- | ----------------- | ------------------------------------------- |
| `max_request_body_buffer`    | `1048576` (1 MiB) | Request bytes retained for inspection       |
| `request_body_limit_action`  | `process_partial` | Request overflow handling                   |
| `inspect_response_body`      | `false`           | Enable response-body capture and processing |
| `max_response_body_buffer`   | `1048576` (1 MiB) | Response bytes retained for inspection      |
| `response_body_limit_action` | `process_partial` | Response overflow handling                  |

## Over the limit

The default, `process_partial`, evaluates the part of the body retained in the buffer. If the rules allow it, OpenShield releases the held data and streams subsequent chunks without further inspection.

With `reject`, an oversized request receives `413`. An oversized response instead has its body replaced with `response blocked`, because its status and headers have already been sent.

**Current limitation:** `reject` checks overflow only on non-final chunks. If the final chunk first exceeds the limit, the truncated prefix is evaluated instead. To block truncation explicitly, put this before other terminal rules in a root ruleset:

```yaml
- id: reject-truncated-request
  phase: request_body
  action: block
  expression: "http.request.body.truncated"
  action_parameters:
    response: { status_code: 413, content: "request body too large" }
```

Because this is a rule, an earlier terminal match can skip it, and detection-only mode disables its enforcement. For an upload limit that applies independently of WAF rules, use a host setting such as nginx's `client_max_body_size`.

## Body sizes and truncation

The `.raw` fields contain the retained bytes, and `.truncated` indicates whether the buffer omitted any received data. The corresponding `.size` records the bytes received when those fields were populated. If inspection ends early and the remaining body streams through, the size stops updating, so it may be smaller than the final transfer.

[Schema validation](../../protections/schema-validation/) reports truncated bodies for matched operations as `body_size` violations instead of validating partial documents.

## What the body phase sees

Alongside `http.request.body.raw`, parsed URL-encoded forms populate `http.request.body.form`, while multipart forms populate `http.request.body.multipart` and its metadata. These parsed fields may be incomplete if the buffer was truncated.

The `request_body` phase also runs for requests without a body, allowing it to check [scores](../../rules/scores/) accumulated from headers. See [Phases](../../rules/phases/) for execution order and [nginx buffering](../../hosts/nginx-module/#what-runs-where) for the module's handling of request bodies.
