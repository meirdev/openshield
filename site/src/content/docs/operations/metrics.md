---
title: Metrics
description: "Prometheus metrics exposed by the proxy."
sidebar:
  order: 3
---

With a `metrics` block in the configuration, the proxy serves Prometheus metrics at `/metrics` on `metrics.listen`, `127.0.0.1:9090` by default:

```yaml
metrics:
  listen: "127.0.0.1:9090"
```

| Metric                            | Type    | Measures                                                                  |
| --------------------------------- | ------- | ------------------------------------------------------------------------- |
| `openshield_requests_total`       | Counter | Requests processed                                                        |
| `openshield_connections_active`   | Gauge   | Active request contexts; despite its name, not a count of TCP connections |
| `openshield_bytes_received_total` | Counter | Request-body bytes seen by the proxy's body filter                        |
| `openshield_bytes_sent_total`     | Counter | Body bytes passed or released by the proxy's response-body filter         |

These metrics are exported alongside Pingora's and reset when the process restarts or reloads. The byte counters measure body data rather than total network traffic, so they exclude HTTP headers. You can inspect the endpoint with:

```bash
curl http://127.0.0.1:9090/metrics
```

To count individual rule matches, use the [audit log](../logs/#audit-log), since the proxy does not expose per-rule metrics. Those counts include only logging-enabled matches and exclude rules skipped during evaluation.
