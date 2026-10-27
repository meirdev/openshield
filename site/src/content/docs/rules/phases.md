---
title: Phases
description: "The five points at which rules run, and what each can see and do."
sidebar:
  order: 2
---

A rule's `phase` says when it runs. Within a phase, rules run in configuration order with executed rulesets expanded in place. The default is `request_headers`.

| Phase | Runs when | Available | Can |
| --- | --- | --- | --- |
| `request_headers` | The request headers arrive | Client IP and GeoIP, URI, headers, cookies, query arguments, JWT results and claims, schema results for parameters | Block, allow, challenge, log, score |
| `request_body` | Body inspection finishes | Everything above, plus the raw body, form fields, multipart parts, schema results for the body | Block, allow, log, score |
| `response_headers` | The upstream's headers arrive | Everything above, plus the response status and headers | Log, score |
| `response_body` | Response body inspection finishes | Everything above, plus the response body | Replace or suppress the body, log, score |
| `logging` | The request is complete | Everything collected | Log, score |

A request phase that blocks sends the rule's response instead of proxying. `response_headers` rules cannot block: the status is already decided. A `response_body` block replaces what is left of the body with the rule's `content` after the headers have been sent, so the client sees the upstream's status with a different body.

Body phases need [body inspection](../../configuration/body-inspection/) and run after the full body, up to the buffer limit, has been read. `request_body` also runs for requests without a body, which matters for [scores](../scores/).

## Choosing a phase

- Put a rule in the earliest phase that has its data: a block in `request_headers` costs nothing further.
- A rule that reads a [score](../scores/) belongs one phase after the rules that add to it, since scores are refreshed between phases.
- Rules on schema body violations or on form fields belong in `request_body`.
- `logging` is for rules that only observe, such as scoring for the audit log.
