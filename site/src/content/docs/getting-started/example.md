---
title: The example
description: "A complete configuration in the repository, with an application to run it against and requests that exercise every rule."
sidebar:
  order: 4
---

The repository's [`examples/`](https://github.com/meirdev/openshield/tree/main/examples) directory is a working deployment in miniature. It is also what the end-to-end test runs, so it always matches the code.

| File | Purpose |
| --- | --- |
| `config.yaml` | Lists, scored injection detection, a rate limit, JWT validation, an OpenAPI schema, text logs |
| `openapi/petstore.yaml` | The schema requests under `/api/v1` are checked against |
| `upstream.py` | The protected application: echoes each request as JSON |
| `token.py` | Mints a JWT the configuration accepts |

## Run it

```bash
cargo build --release
cd examples
python3 upstream.py &
../target/release/openshield -c config.yaml
```

## What each request does

| Request | Result | Why |
| --- | --- | --- |
| `GET /` | `200` | Forwarded; the application echoes it |
| `GET /search?q=1' OR '1'='1` | `403` | SQL injection scored in `request_headers`, blocked in `request_body` |
| `GET /search?q=<script>alert(1)</script>` | `403` | XSS, the same way |
| `GET /` with `User-Agent: sqlmap/1.7` | `403` | Substring list of scanner user agents |
| 6 × `POST /login` within a minute | `429` on the sixth | Rate limit of five per minute per client IP, then a minute of mitigation |
| `GET /api/private/profile` | `401` | No JWT; `is_jwt_valid("api")` is false |
| … with `Authorization: Bearer $(python3 token.py)` | `200` | Valid HS256 token |
| `GET /api/v1/pets?limit=10` | `200` | Matches the schema |
| `GET /api/v1/pets?limit=500` | `400` | `limit` above its maximum |
| `GET /api/v1/owners` | `404` | No such operation in the schema |
| `POST /api/v1/pets` with `{"name":"Rex"}` | `200` | Body matches the schema |
| `POST /api/v1/pets` with `{"species":"dragon"}` | `400` | Required property missing, enum violated |

The commands are in the example's `README.md`, ready to paste.

## Read the logs

The example writes both logs in text format. The access log, one line per request:

```text
2026-10-25T09:44:33.326Z [1ae4c898-…] 127.0.0.1 GET /search?q=1'%20OR%20'1'='1 -> 403 0.412ms waf=block
```

The audit log, one record per request on which rules matched, with the field values that triggered them (`log_payloads: true`):

```text
2026-10-25T09:44:33.326Z [1ae4c898-…] block 127.0.0.1 127.0.0.1:8080 "GET /search?q=1'%20OR%20'1'='1 HTTP/1.1" -> 403
  rules: sqli-args:score, block-injection:block
  scores: sqli=10
  payload http.request.uri.args.values: ["1' OR '1'='1"]
  > host: 127.0.0.1:8080
  > user-agent: curl/8.18.0
```
