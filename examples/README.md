# Example

A complete configuration that exercises OpenShield's features in front of a small echo application. The same setup is run by the end-to-end test in `crates/openshield-pingora/tests/e2e.rs`.

| File                    | Purpose                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `config.yaml`           | Proxy and WAF configuration: lists, scores, JWT, schema, rules |
| `openapi/petstore.yaml` | The API schema requests under `/api/v1` are checked against    |
| `upstream.py`           | The protected application: echoes each request as JSON         |
| `token.py`              | Mints a JWT the `api` token configuration accepts              |

## Run

Build the proxy, then in this directory start the application and the proxy:

```bash
cargo build --release
cd examples
python3 upstream.py &
../target/release/openshield -c config.yaml
```

The access log goes to stdout and the audit log, one record per request on which rules matched, to stderr.

## Try it

Requests the proxy forwards return the echo application's `200` with a JSON copy of the request. Blocked requests return the status and message configured on the rule.

```bash
# Forwarded
curl -i http://127.0.0.1:8080/

# SQL injection and XSS in query arguments are scored, then blocked: 403
curl -i "http://127.0.0.1:8080/search?q=1'%20OR%20'1'='1"
curl -i "http://127.0.0.1:8080/search?q=<script>alert(1)</script>"

# Scanner user agents: 403
curl -i -A "sqlmap/1.7" http://127.0.0.1:8080/

# More than five login attempts per minute: 429 for the next minute
for i in $(seq 6); do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8080/login; done

# A private API needs a valid JWT: 401 without one
curl -i http://127.0.0.1:8080/api/private/profile
curl -i -H "Authorization: Bearer $(python3 token.py)" http://127.0.0.1:8080/api/private/profile

# Requests under /api/v1 must match the OpenAPI document
curl -i "http://127.0.0.1:8080/api/v1/pets?limit=10"          # 200
curl -i "http://127.0.0.1:8080/api/v1/pets?limit=500"         # 400, limit above maximum
curl -i http://127.0.0.1:8080/api/v1/owners                    # 404, unknown endpoint
curl -i -H 'Content-Type: application/json' -d '{"name":"Rex","species":"dog"}' http://127.0.0.1:8080/api/v1/pets   # 200
curl -i -H 'Content-Type: application/json' -d '{"species":"dragon"}' http://127.0.0.1:8080/api/v1/pets              # 400
```

Check a changed configuration without starting the proxy:

```bash
../target/release/openshield --test -c config.yaml
```

## Not included

Turnstile challenges need site and secret keys from Cloudflare; see [Turnstile challenges](https://meirdev.github.io/openshield/protections/turnstile-challenges/) to add a `challenge` block and a rule with `action: challenge`.
