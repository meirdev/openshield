---
title: Schema validation
description: "Check requests against an OpenAPI document and expose every violation to rules."
sidebar:
  order: 3
---

Point a schema at an OpenAPI 3.0 or 3.1 document. OpenShield matches each request to an operation, validates its parameters when the headers arrive and its body when the body arrives, and fills the `schema_validation` fields. Rules decide what a violation means.

```yaml
schemas:
  - name: petstore
    file: ./openapi/petstore.yaml
    hosts: [api.example.com]

rulesets:
  - name: main
    kind: root
    rules:
      - id: unknown-endpoint
        action: block
        expression: 'starts_with(http.request.uri.path, "/api/") and not schema_validation.operation.matched'
        action_parameters: {response: {status_code: 404}}
      - id: invalid-parameters
        action: block
        expression: "schema_validation.violated"
        action_parameters: {response: {status_code: 400, content: "request does not match the API"}}
      - id: invalid-body
        phase: request_body
        action: block
        expression: "schema_validation.violated"
        action_parameters: {response: {status_code: 400, content: "body does not match the API"}}
```

| Setting | Default | Purpose |
| --- | --- | --- |
| `name` | Required | Reported in `schema_validation.schema`; unique |
| `file` | Required | The document, JSON or YAML by extension |
| `hosts` | `[]` | Bare hostnames the schema describes, without port. Empty means any host |

The schema whose `hosts` include the request's `Host` (compared without port, case-insensitively) is used, else the first schema without `hosts`. Hosts no schema covers are not checked and leave the fields unset. The document's `servers` set the base path: with `servers: [{url: /v1}]`, operations are matched under `/v1`; server variables use their `default`.

## What is validated

An operation is matched by method and path (`HEAD` falls back to `GET`); path segments are percent-decoded individually, so an encoded `/` stays inside its segment. Then:

- **Parameters** in path, query, header and cookie, with their OpenAPI `style` and `explode`. `Accept`, `Content-Type` and `Authorization` header parameters are ignored, as the specification says.
- **Content-Type**, when the operation declares a request body and one is present or required.
- **Body**, decoded as JSON, `application/x-www-form-urlencoded` or XML by media type and checked against the schema; other media types are only checked for presence.

OpenAPI 3.0 `nullable` and boolean exclusive bounds are honoured, `readOnly` properties are not required of requests, local `$ref`s resolve. Undeclared query parameters are reported but are not violations. A body larger than `max_request_body_buffer` is a `body_size` violation rather than validated in part.

## Fields

| Field | Type | Value |
| --- | --- | --- |
| `schema_validation.schema` | String | Name of the schema that applies |
| `schema_validation.operation.matched` | Boolean | An operation matched the method and path |
| `schema_validation.operation.template` | String | The matched template, such as `/pets/{id}` |
| `schema_validation.violated` | Boolean | The request does not conform |
| `schema_validation.{path,query,headers,cookies,body}.violated_parameters` | Array<String> | Parameter names, or JSON pointers into the body, with violations |
| `schema_validation.query.undeclared_parameters` | Array<String> | Query parameters the operation does not declare |
| `schema_validation.violation_details.location` | String | `path`, `query`, `header`, `cookie` or `body` of the first violation |
| `schema_validation.violation_details.error_class` | String | Its category, below |
| `schema_validation.violation_details.error_detail` | String | What failed: `expected:integer`, `pattern_no_match`, `maximum`, … |
| `schema_validation.violation_details.target` | String | The parameter name or JSON pointer |

Parameter results are set with the headers; `body.violated_parameters` after body inspection. `violation_details` keep the first violation, parameters before body. On an unmatched operation, `violated` is `false` and the arrays are empty.

| `error_class` | Meaning |
| --- | --- |
| `missing_required` | A required parameter, body or property is absent |
| `invalid_type` | Wrong JSON type |
| `constraint_violation` | A schema keyword failed: `enum`, `pattern`, `minimum`, `format`, … |
| `duplicate_value` | A `uniqueItems` array repeats a value |
| `invalid_encoding` | Bad percent-encoding, UTF-8 or parameter serialization |
| `invalid_syntax` | The body is not well-formed JSON or XML |
| `invalid_media_type` | `Content-Type` missing or malformed |
| `unsupported_media_type` | `Content-Type` not accepted by the operation |
| `body_size` | The body exceeded the inspection buffer |

```text
# Only type errors in the query string
schema_validation.violation_details.location == "query" and schema_validation.violation_details.error_class == "invalid_type"

# Rate limit per operation rather than per path
ratelimit:
  characteristics: [ip.src, schema_validation.operation.template]
```

The validator is the standalone `openshield-openapi` crate and can be used without the rest of OpenShield.
