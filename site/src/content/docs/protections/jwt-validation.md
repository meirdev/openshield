---
title: JWT validation
description: "Verify JSON Web Tokens against configured keys and use their claims in rules."
sidebar:
  order: 2
---

A token configuration says where a JWT is on the request and which keys may have signed it. OpenShield verifies the token before the `request_headers` rules run; the rules then use `is_jwt_valid`, `is_jwt_present` and the claim fields to decide.

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
      - id: api-needs-token
        action: block
        expression: 'starts_with(http.request.uri.path, "/api/") and not is_jwt_valid("api")'
        action_parameters:
          response: {status_code: 401, content: "invalid or missing token"}
```

| Setting | Default | Purpose |
| --- | --- | --- |
| `id` | Required | How rules refer to this configuration; unique |
| `description` | Omitted | Free text |
| `token_sources` | Required | Expressions that locate the token |
| `credentials.keys` | Required | JSON Web Keys that may have signed it |

## Token sources

A source is an expression over the [request fields](../../reference/fields/) that evaluates to a string. Header names are lowercase; cookie names keep their case. The value may be the bare token or `Bearer ` followed by the token: a capital B and one space, nothing else is stripped.

Sources are tried in order and the first *valid* token wins, so a stale token in a cookie does not hide a good one in the header.

## Keys

Every key needs `kid` and `alg`. A token is verified only by the key whose `kid` and `alg` both match its header, which closes the algorithm-confusion attacks.

| `kty` | `alg` | Requirements |
| --- | --- | --- |
| `RSA` | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512` | Modulus of at least 2048 bits; public key only (`n`, `e`) |
| `EC` | `ES256`, `ES384` | `crv` is `P-256` for `ES256`, `P-384` for `ES384`; public key only (`x`, `y`) |
| `oct` | `HS256`, `HS384`, `HS512` | `k` is the shared secret, unpadded base64url, at least 32, 48 or 64 bytes |

Quote a `kid` that YAML would read as a number. Keys come from the configuration only; there is no JWKS fetching. To rotate, add the new key beside the old, [reload](../../operations/running/#reload), and drop the old key once its tokens have expired. A weak or inconsistent key is a configuration error caught by `--test`.

## What is checked

1. The token's `kid` and `alg` select a key. No `kid`, or no key with that pair: invalid.
2. The signature verifies with that key.
3. `exp` and `nbf`, when present, are checked with 60 seconds of clock skew. A token without `exp` does not expire.

`aud` and `iss` are not checked; compare them in a rule with the claim fields. With `logging.level: debug`, the process log says why each token was rejected.

## Functions

| Function | True when |
| --- | --- |
| `is_jwt_valid("id")` | The request carries a valid token for configuration `id` |
| `is_jwt_present("id")` | Any token source has a value, valid or not |

The argument is a literal; an unknown `id` fails configuration validation.

```text
# Allow anonymous requests, reject invalid tokens
is_jwt_present("api") and not is_jwt_valid("api")

# Either of two issuers
not (is_jwt_valid("api") or is_jwt_valid("partner"))
```

## Claims

The registered claims of a valid token are fields, each a map keyed by configuration `id` with an array of values:

| Field | Type | Claim |
| --- | --- | --- |
| `http.request.jwt.claims.iss` | `Map<Array<String>>` | Issuer |
| `http.request.jwt.claims.sub` | `Map<Array<String>>` | Subject |
| `http.request.jwt.claims.aud` | `Map<Array<String>>` | Audience, one or more values |
| `http.request.jwt.claims.jti` | `Map<Array<String>>` | Token ID |
| `http.request.jwt.claims.iat.sec` | `Map<Array<Integer>>` | Issued at, seconds since the epoch |
| `http.request.jwt.claims.nbf.sec` | `Map<Array<Integer>>` | Not before, seconds since the epoch |

Each has `.names` (the configurations whose token carries the claim) and `.values` (all values). Only valid tokens set them, and a claim of the wrong type is left out. Since a comparison on a missing field is false, write checks as conditions that must hold:

```text
# Wrong issuer, or no token at all
not any(http.request.jwt.claims.iss["api"][*] == "https://issuer.example")

# /admin/ needs the admin audience
starts_with(http.request.uri.path, "/admin/") and not any(http.request.jwt.claims.aud["api"][*] == "admin")

# Rate limit per subject
ratelimit:
  characteristics: [http.request.jwt.claims.sub.values]
```
