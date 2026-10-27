---
title: Metrics
description: "Prometheus metrics exposed by the proxy."
sidebar:
  order: 3
---

With a `metrics` block in the configuration, the proxy serves Prometheus metrics at `/metrics` on `metrics.listen`, `127.0.0.1:9090` by default:

```yaml
metrics:
  listen: "0.0.0.0:9090"
```

| Metric | Type | Measures |
| --- | --- | --- |
| `openshield_requests_total` | Counter | Requests processed |
| `openshield_connections_active` | Gauge | Client connections open now |
| `openshield_bytes_received_total` | Counter | Bytes received from clients |
| `openshield_bytes_sent_total` | Counter | Bytes sent to clients |

Pingora's own metrics are exported alongside. Rule-level counts are not metrics; derive them from the audit log, where every match is recorded with its rule ID.
