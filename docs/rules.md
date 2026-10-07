# Rules

Rules live in rulesets. Each rule needs an `id`, an `action`, and a Wirefilter `expression`. Add rules to a ruleset with `kind: root` in the order they should run:

```yaml
rulesets:
  - name: main
    kind: root
    rules:
      - id: block-admin
        phase: request_headers
        action: block
        expression: 'http.request.uri.path == "/admin"'
```

Every rule also accepts these optional fields:

| Field         | Default | Description                                            |
| ------------- | ------- | ------------------------------------------------------ |
| `description` | Omitted | Human-readable description                             |
| `categories`  | `[]`    | Tags that [`execute` overrides](#overrides) can target |
| `ref`         | Omitted | External reference, such as a URL or upstream rule ID  |
| `version`     | Omitted | Rule version                                           |
| `enabled`     | `true`  | Set to `false` to skip the rule                        |

## Rulesets

A ruleset is a named list of rules. Its `kind` decides when the rules run:

| Kind      | Runs                                                                                        |
| --------- | ------------------------------------------------------------------------------------------- |
| `root`    | On every request. Root rulesets run in configuration order                                  |
| `custom`  | Only when a root rule runs it with `action: execute`. This is the default                   |
| `managed` | Same as `custom`. Use it to mark rulesets maintained elsewhere, such as a vendored rule set |

Ruleset names must be unique. `description` and `version` are optional.

A root rule with `action: execute` runs the custom or managed ruleset named in `action_parameters.id`. The ruleset’s rules take the place of the `execute` rule, in order, and each keeps its own phase:

```yaml
rulesets:
  - name: managed
    description: Shared detection rules
    version: "1.0.0"
    rules:
      - id: sqli-args
        categories: [sqli]
        action: block
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
      - id: xss-args
        categories: [xss]
        action: block
        expression: "any(detect_xss(url_decode_uni(http.request.uri.args.values[*])))"

  - name: main
    kind: root
    rules:
      - id: block-admin
        action: block
        expression: 'http.request.uri.path == "/admin"'
      - id: run-managed
        action: execute
        expression: "not ip.src in $allowed_ips"
        action_parameters:
          id: managed
```

The `execute` rule’s expression is added to every rule it runs: a rule from the ruleset matches only when both expressions match. Use `expression: "true"` to run the ruleset unconditionally.

Only root rulesets can contain `execute` rules, and they can only execute custom and managed rulesets. A custom or managed ruleset that no rule executes never runs; OpenShield logs a warning for it at startup.

### Overrides

Add `action_parameters.overrides` to change the action of the executed rules or to enable and disable them, without editing the ruleset:

```yaml
action_parameters:
  id: managed
  overrides:
    action: log # all rules
    enabled: true
    categories:
      - category: sqli
        action: block
    rules:
      - id: xss-args
        enabled: false
```

Rule overrides take precedence over category overrides, which take precedence over the top-level `action` and `enabled`. Each level changes only the settings it specifies. When several categories match a rule, the later entry wins.

An override must name a rule ID or category that exists in the ruleset, and the resulting action must be valid for the rule: overriding to `score` requires the rule to define `action_parameters.scores`, and overriding to `challenge` requires a `challenge` block. `execute` cannot be used as an override action.

## Phases

Rules run in configuration order within each phase, with executed rulesets expanded in place. The default phase is `request_headers`.

| Phase              | Runs when                         | Adds inspection data                              |
| ------------------ | --------------------------------- | ------------------------------------------------- |
| `request_headers`  | Request headers arrive            | Client IP, URI, headers, cookies, query arguments |
| `request_body`     | Request body inspection finishes  | Raw body, form fields, multipart data             |
| `response_headers` | Upstream headers arrive           | Response status and headers                       |
| `response_body`    | Response body inspection finishes | Response body                                     |
| `logging`          | Request processing ends           | Data collected during the request                 |

Body rules inspect up to the configured buffer limit. Response body rules also require `inspect_response_body: true`. See [body inspection](configuration.md#body-inspection) for limits and overflow behavior.

## Actions

| Action      | Effect                                          |
| ----------- | ----------------------------------------------- |
| `block`     | Block the request; default status is `403`      |
| `allow`     | Skip the remaining rules in the current phase   |
| `log`       | Record the match and continue                   |
| `score`     | Update per-request scores and continue          |
| `challenge` | Require [Turnstile verification](challenges.md) |
| `execute`   | Run a [custom or managed ruleset](#rulesets)    |

Enforcement depends on the phase: request header and body rules can block requests; response body rules can replace or suppress the body but cannot change headers already sent. Challenges are served in `request_headers`. The `response_headers` and `logging` phases record matches and update scores without enforcing blocks or challenges.

Rule audit logging is enabled by default. Set `logging: {enabled: false}` on a rule to suppress its audit record without changing its action.

Customize a block response with `action_parameters.response`:

```yaml
action_parameters:
  response:
    status_code: 403
    content_type: text/plain
    content: "Request blocked"
```

## Expressions

Expressions use [Wirefilter](https://github.com/cloudflare/wirefilter) syntax:

```text
# Comparisons and string matching
http.request.method == "POST"
http.response.code >= 400
http.request.uri.path contains "/admin"
http.request.uri.path matches "\\.(php|asp)$"

# List membership and boolean logic
ip.src in $allowed_ips
http.user_agent in $blocked_ua
http.request.method == "POST" and not ip.src in $allowed_ips

# Transforms and detection
detect_sqli(url_decode_uni(http.request.uri.query))
any(detect_xss(lower(http.request.uri.args.values[*])))
regex_capture(http.request.uri.path, "/item/(\\d+)")[1] == "42"
```

### Lists

Define named lists in the configuration and reference them with `$name`.

| `kind`      | Matches when                                                                      |
| ----------- | --------------------------------------------------------------------------------- |
| `ip`        | the address is one of the items or inside one of the CIDRs                        |
| `string`    | the whole value equals one of the items                                           |
| `substring` | any item appears anywhere inside the value (Aho-Corasick, ASCII case-insensitive) |

```yaml
lists:
  - name: allowed_ips
    kind: ip
    items: ["127.0.0.0/8", "10.0.0.0/8"]
  - name: blocked_ua
    kind: string
    items: ["sqlmap", "nikto"]
  - name: scanner_ua
    kind: substring
    items: ["sqlmap", "nikto", "nmap"]
```

```
ip.src in $allowed_ips
http.user_agent in $blocked_ua
http.user_agent in $scanner_ua
```

### Scores

Declare score names in `scores`. A matching `score` rule updates the named counter by `increment` (default: `1`). Scores last for one request and are available in expressions as `score.{name}`.

Score fields are refreshed at the start of each phase. Evaluate a threshold in a later phase to use increments from earlier rules:

```yaml
scores: [sqli]
rulesets:
  - name: main
    kind: root
    rules:
      - id: score-sqli
        phase: request_headers
        action: score
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
        action_parameters:
          scores:
            - name: sqli
              increment: 10

      - id: block-sqli-score
        phase: request_body
        action: block
        expression: "score.sqli >= 10"
```

## Rate limiting

Add `ratelimit` to count matches per key. The rule’s action runs only after the limit is exceeded. This example blocks an IP after more than 100 matching requests in the configured 60-second period:

```yaml
rulesets:
  - name: main
    kind: root
    rules:
      - id: rate-limit-api
        action: block
        expression: 'starts_with(http.request.uri.path, "/api/")'
        ratelimit:
          characteristics: [ip.src]
          period: 60
          requests_per_period: 100
          mitigation_timeout: 120
```

| Parameter             | Meaning                                                                    |
| --------------------- | -------------------------------------------------------------------------- |
| `characteristics`     | Fields that form the key; omitted or empty uses `ip.src`                   |
| `period`              | Counting period in seconds; set explicitly                                 |
| `requests_per_period` | Allowed matches per key; set explicitly                                    |
| `mitigation_timeout`  | Seconds to keep applying the action after exceeding the limit; default `0` |

Use `[ip.src, http.request.uri.path]` for a separate limit per IP and path, or `[http.user_agent]` to group by user agent. Only matches reached during rule evaluation count. Reloading with SIGHUP resets counters.

## Functions

Transforms and detection functions accept a string or an array of strings. Use `[*]` to apply them to array elements and `any` or `all` to combine boolean results.

### Transforms

| Function                                         | Description                                   |
| ------------------------------------------------ | --------------------------------------------- |
| `lower`, `upper`                                 | ASCII case conversion                         |
| `trim`, `trim_start`, `trim_end`                 | Whitespace trimming                           |
| `url_decode_uni`                                 | URL decoding, including `%uXXXX`              |
| `base64_decode`, `base64_encode`                 | Base64 decoding and encoding                  |
| `hex_decode`, `hex_encode`                       | Hex decoding and encoding                     |
| `html_entity_decode`                             | Decode HTML entities                          |
| `md5`, `sha1`                                    | MD5 or SHA-1 hash as a hex string             |
| `utf8_to_unicode`                                | UTF-8 to `\uXXXX` escapes                     |
| `remove_nulls`, `replace_nulls`                  | Remove null bytes or replace them with spaces |
| `remove_whitespace`                              | Strip all ASCII whitespace                    |
| `compress_whitespace`                            | Collapse each whitespace run into one space   |
| `replace_comments`                               | Replace each `/* ... */` with one space       |
| `regex_replace(field, "pattern", "replacement")` | Regex substitution (pattern cached)           |

### Detection

| Function      | Description                            |
| ------------- | -------------------------------------- |
| `detect_sqli` | SQL injection detection (libinjection) |
| `detect_xss`  | XSS detection (libinjection)           |

### Strings

| Function                          | Description                           |
| --------------------------------- | ------------------------------------- |
| `len(field)`                      | String length                         |
| `starts_with(field, "prefix")`    | Prefix check                          |
| `ends_with(field, "suffix")`      | Suffix check                          |
| `regex_capture(field, "pattern")` | Regex capture groups (pattern cached) |

### Aggregation

| Function            | Description                   |
| ------------------- | ----------------------------- |
| `any(array)`        | True if any element is true   |
| `all(array)`        | True if all elements are true |
| `concat(a, b, ...)` | Concatenate strings           |

### JSON

| Function                                     | Description                                    |
| -------------------------------------------- | ---------------------------------------------- |
| `lookup_json_string(field, key1, key2, ...)` | Extract a value from a JSON string by key path |

Use string literals for object keys and integer literals for array indexes. The result is a string; invalid JSON or a missing path returns an empty string.

```text
lookup_json_string(http.request.body.raw, "users", 0, "name") == "alice"
```

### JWT

| Function               | Description                                           |
| ---------------------- | ----------------------------------------------------- |
| `is_jwt_valid("id")`   | True if the request has a valid token                 |
| `is_jwt_present("id")` | True if the request has a token, whether valid or not |

The argument is the `id` of a token configuration. See [JWT validation](jwt.md).

## Fields

Fields become available as the request moves through the phases. GeoIP fields require configured databases; body fields require body inspection; JWT claim fields require a token configuration; schema validation fields require a schema. A field may be absent when the corresponding data is unavailable.

### IP and GeoIP

`ip.src`, `ip.src.asnum`, `ip.src.city`, `ip.src.continent`, `ip.src.country`, `ip.src.lat`, `ip.src.lon`, `ip.src.metro_code`, `ip.src.postal_code`, `ip.src.region`, `ip.src.region_code`, `ip.src.timezone.name`

### Request

`http.cookie`, `http.host`, `http.referer`, `http.user_agent`, `http.x_forwarded_for`, `http.request.method`, `http.request.version`, `http.request.full_uri`, `http.request.uri`, `http.request.uri.path`, `http.request.uri.path.extension`, `http.request.uri.query`, `http.request.timestamp.sec`, `http.request.timestamp.msec`, `ssl`

### Headers, cookies, and query arguments

`http.request.headers`, `http.request.headers.names`, `http.request.headers.values`, `http.request.cookies`, `http.request.cookies.names`, `http.request.cookies.values`, `http.request.uri.args`, `http.request.uri.args.names`, `http.request.uri.args.values`, `http.request.accepted_languages`

### JWT claims

`http.request.jwt.claims.aud`, `http.request.jwt.claims.iss`, `http.request.jwt.claims.jti`, `http.request.jwt.claims.sub`, `http.request.jwt.claims.iat.sec`, `http.request.jwt.claims.nbf.sec`

Each is a map keyed by token configuration `id` and also has `.names` and `.values` arrays. See [JWT validation](jwt.md#claims).

### Schema validation

`schema_validation.schema`, `schema_validation.operation.matched`, `schema_validation.operation.template`, `schema_validation.violated`, `schema_validation.path.violated_parameters`, `schema_validation.query.violated_parameters`, `schema_validation.headers.violated_parameters`, `schema_validation.cookies.violated_parameters`, `schema_validation.body.violated_parameters`, `schema_validation.query.undeclared_parameters`, `schema_validation.violation_details.location`, `schema_validation.violation_details.error_class`, `schema_validation.violation_details.error_detail`, `schema_validation.violation_details.target`

Set when a configured schema covers the request host. See [schema validation](schema-validation.md).

### Request body

`http.request.body.raw`, `http.request.body.size`, `http.request.body.truncated`, `http.request.body.mime`, `http.request.body.form`, `http.request.body.form.names`, `http.request.body.form.values`

### Multipart

`http.request.body.multipart`, `http.request.body.multipart.names`, `http.request.body.multipart.values`, `http.request.body.multipart.filenames`, `http.request.body.multipart.content_types`, `http.request.body.multipart.content_dispositions`, `http.request.body.multipart.content_transfer_encodings`

### Response

`http.response.code`, `http.response.content_type.media_type`, `http.response.headers`, `http.response.headers.names`, `http.response.headers.values`, `http.response.body.raw`, `http.response.body.size`, `http.response.body.truncated`

### Scores

`score.{name}` (dynamic, based on `scores` config)
