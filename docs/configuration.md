# Configuration

OpenShield reads YAML from `config.yaml`, or the file passed with `-c`:

```bash
./target/release/openshield -c config.yaml
```

Only `listen` and `upstream` are required. Without a root ruleset, OpenShield forwards requests without WAF inspection.

```yaml
listen: "127.0.0.1:8080"
upstream: "http://127.0.0.1:3000"
```

Relative file paths resolve from the directory where OpenShield starts.

## Proxy settings

| Setting                   | Default                        | Description                                                                            |
| ------------------------- | ------------------------------ | -------------------------------------------------------------------------------------- |
| `listen`                  | Required                       | Address for incoming requests                                                          |
| `upstream`                | Required                       | Upstream host with an optional port and `http://` or `https://` scheme; omit URL paths |
| `workers`                 | CPU count                      | Number of worker threads                                                               |
| `detection_only`          | `false`                        | Log WAF matches without enforcing blocks or challenges                                 |
| `upstream_keepalive_pool` | Pingora default                | Upstream connection pool size                                                          |
| `pid_file`                | `/tmp/openshield.pid`          | Process ID file                                                                        |
| `upgrade_sock`            | `/tmp/openshield_upgrade.sock` | Socket for transferring listeners during reloads                                       |

## Body inspection

Request body inspection runs when a `request_body` rule exists. Response body inspection requires a `response_body` rule and `inspect_response_body: true`.

| Setting                      | Default                 |
| ---------------------------- | ----------------------- |
| `max_request_body_buffer`    | `1048576` bytes (1 MiB) |
| `request_body_limit_action`  | `process_partial`       |
| `inspect_response_body`      | `false`                 |
| `max_response_body_buffer`   | `1048576` bytes (1 MiB) |
| `response_body_limit_action` | `process_partial`       |

The limit action controls what happens when an inspected body exceeds its buffer:

- `process_partial`: inspect the buffered portion, then stream the remainder uninspected if the rules allow it.
- `reject`: return `413` for an oversized request or suppress an oversized response body.

## TLS

Add `tls` to serve HTTPS. Omit it to serve plain HTTP.

```yaml
tls:
  cert: ./cert.pem
  key: ./key.pem
```

## GeoIP

Provide both MaxMind databases to populate GeoIP fields in rule expressions:

```yaml
geoip:
  city_mmdb: ./GeoLite2-City.mmdb
  asn_mmdb: ./GeoLite2-ASN.mmdb
```

## Logs and metrics

These are the default log settings:

```yaml
logging:
  format: json # json or text
  access_log: /dev/stdout
  audit_log: /dev/stderr
  log_payloads: false
```

Add `metrics` to expose Prometheus metrics. The values below are the defaults when the block is present:

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:9090"
```

See [operations](operations.md) for log contents, application log levels, and metric names.

## Rules and challenges

Define WAF behavior with `rulesets`, named IP or string collections with `lists`, and per-request counters with `scores`. See [rules](rules.md) for examples and the expression reference.

Rules with `action: challenge` also require a `challenge` block. See [Turnstile challenges](challenges.md) for setup.

To verify JSON Web Tokens and use their claims in rules, add `token_configurations`. See [JWT validation](jwt.md) for setup.
