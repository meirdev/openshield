# Operations

## Validate configuration

Check the configuration and compile rule expressions before starting or reloading:

```bash
./target/release/openshield --test -c config.yaml
```

## Reload

Send SIGHUP to the running process. With the default `pid_file`:

```bash
kill -HUP "$(cat /tmp/openshield.pid)"
```

SIGHUP starts a replacement process with `--upgrade`. OpenShield transfers the listening sockets, then drains the old process. The replacement loads configuration, rules, lists, and GeoIP databases. Rate-limit counters reset.

If you changed `pid_file`, use that path in the command.

## Logs

Access and audit logs share a `request_id` so you can trace a WAF decision to its request.

| Log    | Contents                                                                           | Default output |
| ------ | ---------------------------------------------------------------------------------- | -------------- |
| Access | Request metadata, status, duration, and byte counts                                | JSON on stdout |
| Audit  | WAF action, matched rules, scores, request details, and available response details | JSON on stderr |

Audit entries are written when rules match with logging enabled. Set `logging.enabled: false` on an individual rule to omit its match. Set the global `logging.log_payloads: true` to include field values referenced by matched rules.

Configure output paths and JSON or text formatting in [configuration](configuration.md#logs-and-metrics). To extend logging in code, implement `LogSink` or `Formatter`.

Application logs use `RUST_LOG`, which defaults to `openshield=info,pingora=info`. For debug output from OpenShield:

```bash
RUST_LOG=openshield=debug,pingora=info ./target/release/openshield -c config.yaml
```

## Metrics

Add a `metrics` block to expose Prometheus metrics at `/metrics`. The default listener is `127.0.0.1:9090`.

| Metric                            | Type    | Measures                    |
| --------------------------------- | ------- | --------------------------- |
| `openshield_requests_total`       | Counter | Requests processed          |
| `openshield_connections_active`   | Gauge   | Active connections          |
| `openshield_bytes_received_total` | Counter | Bytes received from clients |
| `openshield_bytes_sent_total`     | Counter | Bytes sent to clients       |
