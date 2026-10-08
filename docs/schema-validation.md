# Schema validation

OpenShield can check requests against an OpenAPI document and expose the result to rules: whether the request matched an operation, whether it conforms, and what the first violation was. Rules decide what to do, as with every other detection.

## Setup

Point a schema at an OpenAPI 3.0 or 3.1 document and add rules that use the `schema_validation` fields:

```yaml
schemas:
  - name: pets
    file: ./openapi/pets.yaml
    hosts: [api.example.com]

rulesets:
  - name: main
    kind: root
    rules:
      - id: reject-invalid-requests
        action: block
        expression: "schema_validation.violated"
        action_parameters:
          response:
            status_code: 400
            content: "request does not match the API schema"
      - id: reject-invalid-bodies
        phase: request_body
        action: block
        expression: "schema_validation.violated"
      - id: log-unknown-endpoints
        action: log
        expression: "not schema_validation.operation.matched"
```

| Setting | Default  | Purpose                                                               |
| ------- | -------- | --------------------------------------------------------------------- |
| `name`  | Required | Name reported in `schema_validation.schema`; unique                   |
| `file`  | Required | OpenAPI document, JSON or YAML by file extension                      |
| `hosts` | `[]`     | Bare hostnames the schema describes, without port; empty means every host |

A request is checked against the schema whose `hosts` include its `Host` (compared without port, case-insensitively), or else against the first schema without `hosts`. Requests to a host that no schema covers are not checked and leave every `schema_validation` field unset.

The document's `servers` URLs decide the base path: with `servers: [{url: https://api.example.com/v1}]`, operations are matched under `/v1`. Server variables use their `default`. OpenShield refuses to start when a document does not compile; check with `--test`.

## What is validated

An operation is matched by method and path, with `HEAD` falling back to `GET`. Path segments are percent-decoded individually, so an encoded slash (`%2F`) stays inside its segment. For a matched operation, OpenShield checks:

- **Parameters:** path, query, header and cookie parameters, with their OpenAPI `style` and `explode` serialization. `Accept`, `Content-Type` and `Authorization` header parameters are ignored, as the specification requires.
- **Content-Type:** when the operation declares a request body and the request has one or the body is required.
- **Body:** decoded as JSON, `application/x-www-form-urlencoded` or XML according to its media type, then validated against the schema. Other media types are checked for presence only.

OpenAPI 3.0 `nullable` and boolean `exclusiveMinimum`/`exclusiveMaximum` are honoured, `readOnly` properties are not required in requests, and local `$ref`s are resolved. Query parameters the operation does not declare are reported separately and are not violations.

Parameters are validated when the request headers arrive, so their result is available to `request_headers` rules. The body is validated when body inspection finishes, so rules on body violations belong in the `request_body` phase. A body larger than `max_request_body_buffer` is reported as a `body_size` violation rather than validated.

## Fields

| Field                                               | Type            | Value                                                                 |
| --------------------------------------------------- | --------------- | --------------------------------------------------------------------- |
| `schema_validation.schema`                          | `String`        | Name of the schema that applies to the host                           |
| `schema_validation.operation.matched`               | `Boolean`       | An operation matched the method and path                              |
| `schema_validation.operation.template`              | `String`        | The matched path template, such as `/pets/{id}`                       |
| `schema_validation.violated`                        | `Boolean`       | The request does not conform to the matched operation                 |
| `schema_validation.path.violated_parameters`        | `Array<String>` | Path parameters with violations                                       |
| `schema_validation.query.violated_parameters`       | `Array<String>` | Query parameters with violations                                      |
| `schema_validation.headers.violated_parameters`     | `Array<String>` | Header parameters with violations                                     |
| `schema_validation.cookies.violated_parameters`     | `Array<String>` | Cookie parameters with violations                                     |
| `schema_validation.body.violated_parameters`        | `Array<String>` | JSON pointers into the body with violations; `""` is the whole body   |
| `schema_validation.query.undeclared_parameters`     | `Array<String>` | Query parameters the operation does not declare                       |
| `schema_validation.violation_details.location`      | `String`        | Where the first violation is: `path`, `query`, `header`, `cookie`, `body` |
| `schema_validation.violation_details.error_class`   | `String`        | Category of the first violation; see below                            |
| `schema_validation.violation_details.error_detail`  | `String`        | What was violated, such as `expected:integer` or `pattern_no_match`   |
| `schema_validation.violation_details.target`        | `String`        | Parameter name or JSON pointer of the first violation                 |

The fields exist once a schema applies to the host. `violated`, `operation.*` and the parameter arrays are set with the request headers; `body.violated_parameters` is set after body inspection, or empty when no operation matched. `violation_details` describe the first violation found, parameters before body.

Error classes:

| `error_class`            | Meaning                                                             |
| ------------------------ | ------------------------------------------------------------------- |
| `missing_required`       | A required parameter, body or property is absent                    |
| `invalid_type`           | A value has the wrong JSON type                                     |
| `constraint_violation`   | A schema keyword failed: `enum`, `pattern`, `minimum`, `format`, …  |
| `duplicate_value`        | An array declared `uniqueItems` repeats a value                     |
| `invalid_encoding`       | Bad percent-encoding, UTF-8 or parameter serialization              |
| `invalid_syntax`         | The body is not well-formed JSON or XML                             |
| `invalid_media_type`     | `Content-Type` is missing or malformed                              |
| `unsupported_media_type` | `Content-Type` is not one the operation accepts                     |
| `body_size`              | The body exceeded the inspection buffer                             |

## Examples

```text
# Block requests that do not conform (request_headers phase: parameters only)
schema_validation.violated

# Block unknown endpoints under /api/
starts_with(http.request.uri.path, "/api/") and not schema_validation.operation.matched

# Log only type errors in the query string
schema_validation.violation_details.location == "query"
  and schema_validation.violation_details.error_class == "invalid_type"

# Rate limit by operation instead of by path
ratelimit:
  characteristics: [ip.src, schema_validation.operation.template]
```
