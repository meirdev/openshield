# JWT validation

OpenShield can verify JSON Web Tokens on incoming requests. A token configuration says where to find the token and which keys may have signed it. Rules then decide what to do with requests whose token is missing or invalid, and can inspect the claims of a valid token.

## Setup

Add a token configuration and a rule that uses it:

```yaml
token_configurations:
  - id: api
    token_sources:
      - 'http.request.headers["authorization"][0]'
      - 'http.request.cookies["jwt"][0]'
    credentials:
      keys:
        - kty: EC
          crv: P-256
          kid: "2026-10"
          alg: ES256
          x: QG3VFVwUX4IatQvBy7sqBvvmticCZ-eX5-nbtGKBOfI
          y: A3PXCshn7XcG7Ivvd2K_DerW4LHAlIVKdqhrUnczTD0

rulesets:
  - name: main
    kind: root
    rules:
      - id: require-jwt
        action: block
        expression: 'not is_jwt_valid("api")'
        action_parameters:
          response:
            status_code: 401
            content: "invalid or missing token"
```

| Setting            | Default  | Purpose                                                    |
| ------------------ | -------- | ---------------------------------------------------------- |
| `id`               | Required | Name that rules use to refer to this configuration; unique |
| `description`      | Omitted  | Human-readable description                                 |
| `token_sources`    | Required | Expressions that locate the token on the request           |
| `credentials.keys` | Required | Keys that may have signed the token, as JSON Web Keys      |

### Token sources

Each token source is an expression that evaluates to a string, written with the [request fields](rules.md#fields) available in the `request_headers` phase. Header names in `http.request.headers` are lowercase; cookie names are case-sensitive.

The value may be the bare token or the token after a `Bearer ` prefix. The prefix must match exactly: a capital `B` and one space.

Sources are tried in order, and the first valid token is used. A request with a valid token in any one source passes, even if another source holds an invalid one.

### Keys

Every key needs a `kid` and an `alg`. Quote a `kid` that YAML would read as a number.

| `kty` | `alg`                                                | Requirements                                      |
| ----- | ---------------------------------------------------- | ------------------------------------------------- |
| `RSA` | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512` | Modulus of at least 2048 bits                     |
| `EC`  | `ES256`, `ES384`                                     | `crv` is `P-256` for `ES256`, `P-384` for `ES384` |
| `oct` | `HS256`, `HS384`, `HS512`                            | Secret of at least 32, 48, or 64 bytes in `k`     |

List only public keys for `RSA` and `EC`. For `oct`, `k` is the shared secret encoded as unpadded base64url.

Keys are read from the configuration only; OpenShield does not fetch a JWKS URL. To rotate keys, add the new key next to the old one, [reload](operations.md), and remove the old key once its tokens have expired.

OpenShield refuses to start when a token configuration is invalid. Check it with `--test`.

## How a token is validated

For each token configuration, OpenShield tries the token sources in order. For a source that has a value, it:

1. Reads `kid` and `alg` from the token header and selects the key with the same `kid` and `alg`. A token without a `kid`, or with no matching key, is invalid.
2. Verifies the signature with that key.
3. Checks `exp` and `nbf` when the token has them, allowing 60 seconds of clock skew. A token without `exp` does not expire.

If the token fails a step, the next source is tried. The `aud` and `iss` claims are not checked: compare them in a rule using the [claim fields](#claims).

Tokens are validated once per request, before the `request_headers` rules run. Run OpenShield with [debug logging](operations.md) to see why a token was rejected.

## Rules

Two functions report the result for a token configuration. Both take its `id` as a string literal; an unknown `id` is a configuration error.

| Function               | True when                                  |
| ---------------------- | ------------------------------------------ |
| `is_jwt_valid("id")`   | The request has a valid token              |
| `is_jwt_present("id")` | Any token source has a value, valid or not |

```text
# Block requests without a valid token
not is_jwt_valid("api")

# Allow anonymous requests, but block invalid tokens
is_jwt_present("api") and not is_jwt_valid("api")

# Block unless a token from either of two configurations is valid
not (is_jwt_valid("api") or is_jwt_valid("partner"))
```

To require a token only on part of the site, add a condition to the rule:

```yaml
- id: require-jwt-on-api
  action: block
  expression: 'starts_with(http.request.uri.path, "/api/") and not is_jwt_valid("api")'
```

## Claims

The registered claims of a valid token are available as fields. Each field is a map keyed by token configuration `id`, with an array of values:

| Field                             | Type                  | Claim                              |
| --------------------------------- | --------------------- | ---------------------------------- |
| `http.request.jwt.claims.iss`     | `Map<Array<String>>`  | Issuer                             |
| `http.request.jwt.claims.sub`     | `Map<Array<String>>`  | Subject                            |
| `http.request.jwt.claims.aud`     | `Map<Array<String>>`  | Audience; one or more values       |
| `http.request.jwt.claims.jti`     | `Map<Array<String>>`  | Token ID                           |
| `http.request.jwt.claims.iat.sec` | `Map<Array<Integer>>` | Issued at, in seconds since epoch  |
| `http.request.jwt.claims.nbf.sec` | `Map<Array<Integer>>` | Not before, in seconds since epoch |

Each field also has a `.names` array, listing the token configurations whose token carries the claim, and a `.values` array with all the values.

Only valid tokens set these fields, and a claim of an unexpected type is left out. A comparison on a missing claim is false, so write claim checks as conditions that must hold:

```text
# Block tokens from another issuer
not any(http.request.jwt.claims.iss["api"][*] == "https://issuer.example")

# Block requests under /admin/ whose token lacks the "admin" audience
starts_with(http.request.uri.path, "/admin/") and not any(http.request.jwt.claims.aud["api"][*] == "admin")
```
