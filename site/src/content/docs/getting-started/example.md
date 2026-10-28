---
title: The example
description: "Run the example application and try rules for injection, rate limits, JWTs, and OpenAPI validation."
sidebar:
  order: 4
---

The repository's [`examples/`](https://github.com/meirdev/openshield/tree/main/examples) directory pairs an echo application with the WAF configuration used by the proxy's end-to-end test. It lets you try lists, scores, injection detection, rate limiting, JWTs, and schema validation without supplying GeoIP databases or Turnstile credentials, which are not included.

| File                    | Purpose                                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| `config.yaml`           | Lists, scored injection detection, a rate limit, JWT validation, an OpenAPI schema, text logs |
| `openapi/petstore.yaml` | The schema requests under `/api/v1` are checked against                                       |
| `upstream.py`           | The protected application: echoes each request as JSON                                        |
| `token.py`              | Mints a JWT the configuration accepts                                                         |

## Run it

From the repository root, build the proxy and start the example application:

```bash
cargo build --release --locked
cd examples
python3 upstream.py
```

In a second terminal, from the repository root:

```bash
cd examples
../target/release/openshield --test -c config.yaml
../target/release/openshield -c config.yaml
```

The application listens on port 3000, and OpenShield forwards to it from port 8080. Run requests from a third terminal in `examples/`, then stop each server with `Ctrl+C` when finished. If you adapt the configuration for your own application, replace the sample JWT secret.

## What each request does

| Request                                            | Result             | Why                                                                      |
| -------------------------------------------------- | ------------------ | ------------------------------------------------------------------------ |
| `GET /`                                            | `200`              | Forwarded; the application echoes it                                     |
| `GET /search?q=1' OR '1'='1`                       | `403`              | SQL injection scored in `request_headers`, blocked in `request_body`     |
| `GET /search?q=<script>alert(1)</script>`          | `403`              | XSS, the same way                                                        |
| `GET /` with `User-Agent: sqlmap/1.7`              | `403`              | Substring list of scanner user agents                                    |
| 6 × `POST /login` within a minute                  | `429` on the sixth | Rate limit of five per minute per client IP, then a minute of mitigation |
| `GET /api/private/profile`                         | `401`              | No JWT; `is_jwt_valid("api")` is false                                   |
| … with `Authorization: Bearer $(python3 token.py)` | `200`              | Valid HS256 token                                                        |
| `GET /api/v1/pets?limit=10`                        | `200`              | Matches the schema                                                       |
| `GET /api/v1/pets?limit=500`                       | `400`              | `limit` above its maximum                                                |
| `GET /api/v1/owners`                               | `404`              | No such operation in the schema                                          |
| `POST /api/v1/pets` with `{"name":"Rex"}`          | `200`              | Body matches the schema                                                  |
| `POST /api/v1/pets` with `{"species":"dragon"}`    | `400`              | Required property missing, enum violated                                 |

The commands are in the example's `README.md`, ready to paste.

## Read the logs

The example writes both logs in text format. Every request produces an access-log line showing its HTTP outcome:

```text
2026-10-25T09:44:33.326Z [1ae4c898-…] 127.0.0.1 GET /search?q=1'%20OR%20'1'='1 -> 403 0.412ms waf=block
```

When rules match, the request also produces an audit record. Because the example enables `log_payloads`, that record includes the field values that triggered those rules:

```text
2026-10-25T09:44:33.326Z [1ae4c898-…] block 127.0.0.1 127.0.0.1:8080 "GET /search?q=1'%20OR%20'1'='1 HTTP/1.1" -> 403
  rules: sqli-args:score, block-injection:block
  scores: sqli=10
  payload http.request.uri.args.values: ["1' OR '1'='1"]
  > host: 127.0.0.1:8080
  > user-agent: curl/8.18.0
```
