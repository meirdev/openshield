---
title: Scores
description: "Per-request counters that let several weak signals add up to one decision."
sidebar:
  order: 6
---

Scores are named integers that start at zero for each request. A matching `score` rule adds an increment and continues evaluation. A rule in a later phase can compare the accumulated score with a threshold.

This WAF fragment adds points for SQL injection signals in query arguments and cookies, then checks the total in `request_body`:

```yaml
scores: [sqli, xss]

rulesets:
  - name: main
    kind: root
    rules:
      - id: sqli-args
        action: score
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
        action_parameters:
          scores: [{name: sqli, increment: 10}]
      - id: sqli-cookies
        action: score
        expression: "any(detect_sqli(url_decode_uni(http.request.cookies.values[*])))"
        action_parameters:
          scores: [{name: sqli, increment: 5}]

      - id: block-injection
        phase: request_body
        action: block
        expression: "score.sqli >= 10"
```

Declare each name in the top-level `scores` list to make it available as `score.{name}`. A matching rule adds its `increment`, which defaults to `1` and may be negative. In this example, one query-argument match adds enough points to block on its own, so the threshold still needs tuning for false positives.

Score fields are refreshed at the start of each phase. That is why the example checks header-phase scores in `request_body`, which also runs for requests without a body. Points added during the body phase are not visible to other rules in that same phase; use a direct blocking expression if a body detection must be enforced immediately.

The final scores appear in the audit record and are discarded after the request. To count activity across requests, use [Rate limiting](../rate-limiting/).
