---
title: Phases
description: "The five points at which rules run, and what each can see and do."
sidebar:
  order: 2
---

A rule's `phase` selects the data and point in the lifecycle at which it runs. The default is `request_headers`. Within each phase, rules run in configuration order, with executed rulesets expanded in place.

| Phase | Runs when | Available | Can |
| --- | --- | --- | --- |
| `request_headers` | The request headers arrive | Client IP and GeoIP, URI, headers, cookies, query arguments, JWT results and claims, schema results for parameters | Block, allow, challenge, log, score |
| `request_body` | Body inspection finishes | Everything above, plus the raw body, form fields, multipart parts, schema results for the body | Block, allow, log, score |
| `response_headers` | The upstream's headers arrive | Everything above, plus the response status and headers | Log, score |
| `response_body` | Response body inspection finishes | Everything above, plus the response body | Replace or suppress the body, log, score |
| `logging` | The request is complete | Everything collected | Log, score |

A block in a request phase sends the rule's response instead of forwarding the request body. The proxy and nginx hosts do not enforce block verdicts from `response_headers` or `logging`. A `response_body` block changes the remaining body, while the client keeps the upstream's status and headers.

Although the table describes effects supported by the supplied hosts, a terminal action (`block`, `allow`, or `challenge`) stops phase evaluation even where its verdict is ignored. For that reason, use `log` or `score` to observe traffic in response-header and logging phases, and place challenges in `request_headers`.

Body phases evaluate at end of stream or when partial processing reaches the inspection limit; they do not necessarily see the entire body. `request_body` also runs for requests without a body, which matters for [scores](../scores/). See [Body inspection](../../configuration/body-inspection/) for buffering and truncation.

A request blocked in `request_headers` does not proceed through the upstream phases. The logging phase can still record it, but fields from phases that never ran will not be available.

## Choosing a phase

Choose the earliest phase that has the data a rule needs. A header-phase block avoids sending the request upstream, while rules that inspect form fields or schema body violations must wait for `request_body`.

Rules that read [scores](../scores/) also need a later phase than the rules that increment them, because score fields refresh between phases. Use `logging` for decisions that only contribute to the audit record, after the response has been handled.
