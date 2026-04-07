# OpenShield

<div align="center" style="margin-bottom: 50px;">
  <img src="./assets/logo.png" alt="OpenShield Logo" width="500"/>
</div>

High-performance reverse proxy with Web Application Firewall (WAF) capabilities, built on [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [Cloudflare Wirefilter](https://github.com/cloudflare/wirefilter).

## Features

- Flexible expression-based rules using Cloudflare's wirefilter engine
- Multi-phase request/response inspection (headers, body, response)
- SQL injection and XSS detection via libinjection
- GeoIP lookups (MaxMind)
- Rate limiting with sliding windows
- Score-based threat detection (accumulate across rules)
- IP and string list matching
- Hot config reload via SIGHUP (rules, lists, GeoIP databases)
- Structured logging (JSON/text) with pluggable sinks
- Prometheus metrics
- TLS termination with HTTP/2

## Quick Start

```bash
cargo build --release
./target/release/openshield -c config.yaml
```

## Configuration

```yaml
listen: "127.0.0.1:8080"
upstream: "https://httpbin.org"

max_request_body_buffer: 1048576 # 1MB
inspect_response_body: false
max_response_body_buffer: 1048576

tls: # optional
  cert: ./cert.pem
  key: ./key.pem

logging:
  level: info # debug/info/warn/error
  format: json # json/text
  access_log: /dev/stdout
  audit_log: /dev/stderr

geoip: # optional
  city_mmdb: ./GeoLite2-City.mmdb
  asn_mmdb: ./GeoLite2-ASN.mmdb

metrics: # optional
  enabled: true
  listen: "127.0.0.1:9090"

challenge: # optional
  turnstile_site_key: "0x4AAAAAAA..."
  turnstile_secret_key: "0x4AAAAAAA..."
  cookie_secret: "your-random-secret-key"

scores:
  - sqli
  - xss

lists:
  - name: allowed_ips
    kind: ip
    items:
      - "127.0.0.0/8"
      - "10.0.0.0/8"

  - name: blocked_ua
    kind: string
    items:
      - "sqlmap"
      - "nikto"

rules:
  - id: detect-sqli
    phase: request_headers
    action: score
    expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
    action_parameters:
      scores:
        - name: sqli
          increment: 10

  - id: block-bad-ua
    phase: request_headers
    action: block
    expression: "http.user_agent in $blocked_ua"

  - id: rate-limit
    phase: request_headers
    action: block
    expression: "not ip.src in $allowed_ips"
    ratelimit:
      characteristics: [ip.src]
      period: 10
      requests_per_period: 100
      mitigation_timeout: 30
```

## Rule Expressions

Rules use [wirefilter](https://github.com/cloudflare/wirefilter) syntax:

```
# Comparison operators
http.request.method == "POST"
http.response.code >= 400
http.request.uri.path contains "/admin"
http.request.uri.path matches "\\.(php|asp)$"

# List membership
ip.src in $allowed_ips
http.user_agent in $blocked_ua

# Boolean logic
http.request.method == "POST" and not ip.src in $allowed_ips

# Functions (polymorphic - work on scalars and arrays)
detect_sqli(url_decode_uni(http.request.uri.query))
any(detect_xss(lower(http.request.uri.args.values[*])))
regex_capture(http.request.uri.path, "/item/(\\d+)")[1] == "42"
```

### Phases

Rules execute in order within each phase:

| Phase              | When                     | Available Fields                      |
| ------------------ | ------------------------ | ------------------------------------- |
| `request_headers`  | After headers received   | IP, headers, URI, cookies, query args |
| `request_body`     | After full body received | + body, form data, multipart          |
| `response_headers` | After upstream responds  | + response status, headers            |
| `response_body`    | After response body      | + response body                       |
| `logging`          | End of request cycle     | All fields                            |

### Actions

| Action      | Behavior                                 |
| ----------- | ---------------------------------------- |
| `block`     | Return error response (default 403)      |
| `allow`     | Skip remaining rules in phase            |
| `log`       | Record to audit log, continue processing |
| `score`     | Increment score counters                 |
| `challenge` | Issue Turnstile challenge (see below)    |

### Functions

**Transforms** (Bytes -> Bytes, also work on arrays):

| Function                                   | Description                  |
| ------------------------------------------ | ---------------------------- |
| `lower`, `upper`                           | Case conversion              |
| `trim`, `trim_start`, `trim_end`           | Whitespace trimming          |
| `url_decode_uni`                           | URL decode (supports %uXXXX) |
| `base64_decode`, `base64_encode`           | Base64                       |
| `hex_decode`, `hex_encode`                 | Hex encoding                 |
| `html_entity_decode`                       | HTML entity decode           |
| `sha1`                                     | SHA1 hash (hex output)       |
| `utf8_to_unicode`                          | UTF-8 to \uXXXX              |
| `remove_nulls`, `replace_nulls`            | Null byte handling           |
| `remove_whitespace`, `compress_whitespace` | Whitespace normalization     |
| `replace_comments`, `remove_comments_char` | SQL comment handling         |

**Detection** (Bytes -> Bool, also work on arrays):

| Function      | Description                            |
| ------------- | -------------------------------------- |
| `detect_sqli` | SQL injection detection (libinjection) |
| `detect_xss`  | XSS detection (libinjection)           |

**String** (non-polymorphic):

| Function                          | Description                          |
| --------------------------------- | ------------------------------------ |
| `len(field)`                      | String length                        |
| `starts_with(field, "prefix")`    | Prefix check                         |
| `ends_with(field, "suffix")`      | Suffix check                         |
| `regex_capture(field, "pattern")` | Regex capture groups (returns array) |

**Built-in**:

| Function            | Description                   |
| ------------------- | ----------------------------- |
| `any(array)`        | True if any element is true   |
| `all(array)`        | True if all elements are true |
| `concat(a, b, ...)` | Concatenate strings           |

### Fields

<details>
<summary>All available fields</summary>

**IP / GeoIP:**
`ip.src`, `ip.src.asnum`, `ip.src.city`, `ip.src.continent`, `ip.src.country`, `ip.src.lat`, `ip.src.lon`, `ip.src.metro_code`, `ip.src.postal_code`, `ip.src.region`, `ip.src.region_code`, `ip.src.timezone.name`

**Request:**
`http.cookie`, `http.host`, `http.referer`, `http.user_agent`, `http.x_forwarded_for`, `http.request.method`, `http.request.version`, `http.request.full_uri`, `http.request.uri`, `http.request.uri.path`, `http.request.uri.path.extension`, `http.request.uri.query`, `http.request.timestamp.sec`, `http.request.timestamp.msec`, `ssl`

**Request Headers/Cookies/Args (maps and arrays):**
`http.request.headers`, `http.request.headers.names`, `http.request.headers.values`, `http.request.cookies`, `http.request.cookies.names`, `http.request.cookies.values`, `http.request.uri.args`, `http.request.uri.args.names`, `http.request.uri.args.values`, `http.request.accepted_languages`

**Request Body:**
`http.request.body.raw`, `http.request.body.size`, `http.request.body.truncated`, `http.request.body.mime`, `http.request.body.form`, `http.request.body.form.names`, `http.request.body.form.values`

**Multipart:**
`http.request.body.multipart`, `http.request.body.multipart.names`, `http.request.body.multipart.values`, `http.request.body.multipart.filenames`, `http.request.body.multipart.content_types`, `http.request.body.multipart.content_dispositions`, `http.request.body.multipart.content_transfer_encodings`

**Response:**
`http.response.code`, `http.response.content_type.media_type`, `http.response.headers`, `http.response.headers.names`, `http.response.headers.values`, `http.response.body.raw`, `http.response.body.size`, `http.response.body.truncated`

**Scores:**
`oss.waf.score.{name}` (dynamic, based on `scores` config)

</details>

## Challenge (Turnstile)

When a rule triggers with `action: challenge`, OpenShield presents a [Cloudflare Turnstile](https://www.cloudflare.com/products/turnstile/) widget to verify the client is human.

### Flow

1. Rule matches with `action: challenge`
2. OpenShield checks for a valid `oss_challenge` cookie (HMAC-signed, bound to client IP)
3. If valid — request passes through to upstream
4. If not — serves the Turnstile challenge page (403)
5. Client solves the widget — browser POSTs the token to the challenge endpoint
6. OpenShield verifies the token with Cloudflare's siteverify API
7. On success — sets signed cookie and redirects to the original URL
8. On failure — shows the challenge again

### Configuration

```yaml
challenge:
  turnstile_site_key: "0x4AAAAAAA..."
  turnstile_secret_key: "0x4AAAAAAA..."
  cookie_secret: "your-random-secret-key"
  cookie_ttl: 3600 # seconds (default: 3600)
  cookie_name: "oss_challenge" # default
  challenge_path: "/__openshield/challenge" # default
  custom_page: ./challenge.html # optional
```

### Custom Challenge Page

Provide your own HTML file via `custom_page`. The following placeholders are replaced:

- `{{turnstile_site_key}}` — the Turnstile site key
- `{{challenge_path}}` — the verification endpoint path

The form must POST to `{{challenge_path}}` and include:

- The Turnstile response field (`cf-turnstile-response`, added automatically by the widget)
- A hidden `redirect` field with the original URL

### Example Rule

```yaml
rules:
  - id: challenge-suspicious
    phase: request_headers
    action: challenge
    expression: "not ip.src in $allowed_ips"
```

## Hot Reload

Send SIGHUP to reload config, rules, lists, and GeoIP databases without downtime:

```bash
kill -HUP $(pidof openshield)
```

Rate limit counters are preserved across reloads.

## Logging

**Access log** — one entry per request:

```json
{
  "request_id": "550e8400-...",
  "timestamp": "2024-01-15T10:30:00.123Z",
  "client_ip": "1.2.3.4",
  "method": "GET",
  "protocol": "HTTP/1.1",
  "host": "example.com",
  "path": "/api/users",
  "query": "id=1",
  "status": 200,
  "duration_ms": 12.5,
  "bytes_received": 0,
  "bytes_sent": 1234
}
```

**Audit log** — only when WAF rules match, correlated by `request_id`:

```json
{"request_id":"550e8400-...","timestamp":"2024-01-15T10:30:00.123Z","waf_action":"block","waf_rule_id":"detect-sqli","waf_matched_rules":[{"id":"detect-sqli","action":"score"}],"waf_scores":{"sqli":10},"request":{"client_ip":"1.2.3.4","method":"GET","protocol":"HTTP/1.1","host":"example.com","path":"/api/users","query":"id=1' OR 1=1","headers":{...},"body":null,"body_size":0}}
```

The logging system supports custom sinks and formatters via the `LogSink` and `Formatter` traits.

## Metrics

Prometheus metrics available at `http://127.0.0.1:9090/metrics` (configurable).
