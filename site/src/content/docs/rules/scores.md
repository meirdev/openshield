---
title: Scores
description: "Per-request counters that let several weak signals add up to one decision."
sidebar:
  order: 6
---

Scores are per-request integers. Rules with `action: score` add to them, and a later rule decides on the total, the way anomaly scoring works in ModSecurity's Core Rule Set.

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

- Declare every score name in the top-level `scores` list; `score.{name}` is then a field.
- `increment` defaults to `1` and may be negative.
- Scores are refreshed at the start of each phase. A rule that reads a score must run in a later phase than the rules that add to it; `request_body` is the natural place to check scores from `request_headers`, and it runs for requests without a body too.
- Scores last for one request and appear in the audit record.
