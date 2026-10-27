---
title: Rate limiting
description: "Count matches per key and act only past a limit."
sidebar:
  order: 7
---

Add `ratelimit` to a rule to count its matches per key. The rule's action runs only once the limit is exceeded:

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
    response: {status_code: 429, content: "too many attempts"}
```

| Parameter | Meaning |
| --- | --- |
| `characteristics` | Fields whose values form the key. Empty or omitted means `ip.src` |
| `period` | Counting window in seconds |
| `requests_per_period` | Matches allowed per key within the window |
| `mitigation_timeout` | Seconds to keep applying the action after the limit is exceeded; `0` re-evaluates every request |

The key can be any combination of fields: `[ip.src, http.request.uri.path]` limits each client per path, `[http.request.jwt.claims.sub.values]` limits per token subject, `[ip.src, schema_validation.operation.template]` limits per client per API operation.

Only matches count: a request the expression does not match neither counts nor is blocked. Counts are approximate, in the way a count-min sketch is.

## Where counts live

In the proxy, counters are in memory and per process; a [reload](../../operations/running/#reload) starts a new process and resets them. In the [nginx module](../../hosts/nginx-module/), counters are in a shared memory zone, so all workers count together and counts survive a reload.
