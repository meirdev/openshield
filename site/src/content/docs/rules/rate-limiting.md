---
title: Rate limiting
description: "Count matches per key and act only past a limit."
sidebar:
  order: 7
---

Add `ratelimit` to a rule to count matching requests per key. The rule acts only after the count exceeds `requests_per_period`. Put this fragment under a root ruleset's `rules:`:

```yaml
- id: login-attempts
  action: block
  expression: 'http.request.method == "POST" and http.request.uri.path == "/login"'
  ratelimit:
    characteristics: [ip.src]
    period: 60
    requests_per_period: 5
    mitigation_timeout: 300
  action_parameters:
    response: { status_code: 429, content: "too many attempts" }
```

| Parameter             | Meaning                                                                                         |
| --------------------- | ----------------------------------------------------------------------------------------------- |
| `characteristics`     | Fields whose values form the key. Empty or omitted means `ip.src`                               |
| `period`              | Counting window in seconds                                                                      |
| `requests_per_period` | Matches allowed per key within the window                                                       |
| `mitigation_timeout`  | Seconds to keep applying the action after the limit is exceeded; `0` re-evaluates every request |

In this example, the sixth matching request in a fresh window returns `429` and starts a 300-second mitigation period. Once that period expires, the next matching request is checked against the current count; expiry does not reset it.

The `characteristics` field selects which requests share a counter. For example, `[ip.src, http.request.uri.path]` counts each client's requests to each path separately, while `[http.request.jwt.claims.sub.values]` groups requests by their combined token subjects. These entries must be field names, not expressions.

Missing fields contribute nothing to the key, so requests without those values can share a counter. A token-based rule should therefore require a valid token and subject. Similarly, when using `[ip.src, schema_validation.operation.template]`, guard the rule with `schema_validation.operation.matched`.

Only requests that reach the rule and match its expression count toward the limit. The counter also includes the rule ID, so give rate-limited rules distinct IDs to keep their counts separate.

## Where counts live

The proxy uses Pingora's count-min-sketch estimator, shared across threads in one process. A [reload](../../operations/running/#reload) starts a new process and resets those counts.

The [nginx module](../../hosts/nginx-module/) instead stores per-key window estimates in shared memory, allowing counts to survive reloads when the zone size stays the same. Changing a rule's period resets its counter. If the zone fills and no entries can be reclaimed, the module allows the request and logs a warning.

Both stores provide estimates for traffic control rather than exact billing counts, and neither shares them across independent instances.
