---
title: Proxy settings
description: "Listening, the upstream, TLS, workers and metrics for the openshield proxy."
sidebar:
  order: 2
---

These keys configure the `openshield` binary. The [nginx module](../../hosts/nginx-module/) does not read them; nginx's own directives play their role.

| Setting                   | Default                        | Description                                                                                                       |
| ------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `listen`                  | Required                       | Address to accept requests on, such as `0.0.0.0:443`                                                              |
| `upstream`                | Required                       | The application: `http://` or `https://`, host and optional port, no path                                         |
| `tls`                     | Omitted                        | Serve HTTPS with `cert` and `key` files; see below                                                                |
| `workers`                 | CPU count                      | Worker threads                                                                                                    |
| `upstream_keepalive_pool` | Pingora default                | Size of the pool of idle connections to the upstream                                                              |
| `pid_file`                | `/tmp/openshield.pid`          | Where the process ID is written                                                                                   |
| `upgrade_sock`            | `/tmp/openshield_upgrade.sock` | Unix socket used to hand listening sockets to a replacement process on [reload](../../operations/running/#reload) |
| `metrics`                 | Omitted                        | Expose Prometheus metrics; see below                                                                              |

## TLS

```yaml
tls:
  cert: ./cert.pem
  key: ./key.pem
```

Adding `tls` enables HTTPS and HTTP/2 on the listener; omitting it leaves the listener on plain HTTP. The upstream connection is configured independently by the scheme in `upstream`.

## Metrics

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:9090"
```

The values shown are the defaults when the block is present. Metrics are served at `/metrics` on that address; the names are listed under [Metrics](../../operations/metrics/).

## Client addresses and forwarded headers

In the standalone proxy, `ip.src` is the address of the immediate TCP peer. An incoming `X-Forwarded-For` header is available as `http.x_forwarded_for`, but does not replace `ip.src`. Behind a load balancer, IP-based rules, GeoIP, and IP-based rate limits therefore use the load balancer's address.

When forwarding to the application, the proxy sets `Host` to the configured upstream host and port, preserves the original host in `X-Forwarded-Host`, and sets `X-Forwarded-Proto` and `X-Real-IP` from the connection. It appends the peer address to an existing `X-Forwarded-For` value. Configure the application's trusted-proxy handling accordingly; the header's earlier entries may have been supplied by the client.
