---
title: Body inspection
description: "When bodies are buffered, how much, and what happens when they are larger than the buffer."
sidebar:
  order: 3
---

Bodies are only read when a rule needs them. Request body inspection runs when any `request_body` rule exists; response body inspection needs a `response_body` rule *and* `inspect_response_body: true`, because holding responses has a cost on every request.

| Setting | Default | Description |
| --- | --- | --- |
| `max_request_body_buffer` | `1048576` (1 MiB) | Bytes of a request body kept for inspection |
| `request_body_limit_action` | `process_partial` | What to do when a request body is larger |
| `inspect_response_body` | `false` | Enable response body inspection |
| `max_response_body_buffer` | `1048576` (1 MiB) | Bytes of a response body kept for inspection |
| `response_body_limit_action` | `process_partial` | What to do when a response body is larger |

## Over the limit

- `process_partial` inspects the buffered part. If the rules allow it, the buffered part is released and the remainder streams through uninspected.
- `reject` answers an oversized request with `413` and, for an oversized response, suppresses the body.

The fields tell rules what happened: `http.request.body.truncated` and `http.response.body.truncated` are `true` when a body was cut at the limit, and `http.request.body.size` is the full size, not the buffered one. [Schema validation](../../protections/schema-validation/) reports a truncated request body as a `body_size` violation instead of validating part of it.

## What the body phase sees

In `request_body`, the raw body is in `http.request.body.raw`. Form bodies (`application/x-www-form-urlencoded`) are parsed into `http.request.body.form`, and multipart bodies into `http.request.body.multipart` with the parts' names, values, filenames and content types. The body phase also runs for requests without a body, so rules placed there to read [scores](../../rules/scores/) from the header phase work for `GET` requests too.
