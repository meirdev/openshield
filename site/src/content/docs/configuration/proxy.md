---
title: Proxy settings
description: "Listening, the upstream, TLS, workers and metrics for the openshield proxy."
sidebar:
  order: 2
---

These keys configure the `openshield` binary. The [nginx module](../../hosts/nginx-module/) does not read them; nginx's own directives play their role.

| Setting | Default | Description |
| --- | --- | --- |
| `listen` | Required | Address to accept requests on, such as `0.0.0.0:443` |
| `upstream` | Required | The application: `http://` or `https://`, host and optional port, no path |
| `tls` | Omitted | Serve HTTPS with `cert` and `key` files; see below |
| `workers` | CPU count | Worker threads |
| `upstream_keepalive_pool` | Pingora default | Size of the pool of idle connections to the upstream |
| `pid_file` | `/tmp/openshield.pid` | Where the process ID is written |
| `upgrade_sock` | `/tmp/openshield_upgrade.sock` | Unix socket used to hand listening sockets to a replacement process on [reload](../../operations/running/#reload) |
| `metrics` | Omitted | Expose Prometheus metrics; see below |

## TLS

```yaml
tls:
  cert: ./cert.pem
  key: ./key.pem
```

With `tls`, the listener speaks HTTPS with HTTP/2 enabled. Without it, plain HTTP. The connection to the upstream is independent and follows the scheme in `upstream`.

## Metrics

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:9090"
```

The values shown are the defaults when the block is present. Metrics are served at `/metrics` on that address; the names are listed under [Metrics](../../operations/metrics/).
