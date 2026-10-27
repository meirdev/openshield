---
title: Introduction
description: "What OpenShield is, how a request moves through it, and where it runs."
sidebar:
  order: 1
---

OpenShield is a web application firewall. It sits in front of your application, inspects every request and response, and enforces rules you write in a small expression language. It is written in Rust, runs as a reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora) or as an [nginx module](../../hosts/nginx-module/), and uses [Wirefilter](https://github.com/cloudflare/wirefilter), the expression language behind Cloudflare's firewall rules.

## A rule is an expression and an action

```yaml
rulesets:
  - name: main
    kind: root
    rules:
      - id: block-sqli
        action: block
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
```

The expression reads like the thing it checks: decode every query argument, run SQL injection detection on each, block if any triggers. Everything OpenShield knows about a request is a **field** (`http.request.uri.path`, `ip.src.country`, `http.request.jwt.claims.sub`), and everything it can compute is a **function** (`detect_sqli`, `lower`, `is_jwt_valid`). Rules combine them with `and`, `or`, `not`, comparisons, regular expressions and list membership.

## Detections become fields, rules decide

Features that would be separate products elsewhere are detections that fill fields, and your rules decide what to do:

- **Injection detection** with libinjection, behind transforms that undo the encodings attackers use.
- **JWT validation** against keys you configure, with the token's claims exposed as fields.
- **Schema validation** of requests against an OpenAPI document, with every violation exposed as fields.
- **GeoIP**, **IP and string lists**, **per-request scores** and **rate limits** by any combination of fields.
- **Turnstile challenges** for suspicious clients.

Because the results are fields, one rule can say "block requests to `/admin/` whose token lacks the `admin` audience" or "rate limit by API operation instead of by path".

## Five phases

A request passes through five phases, and a rule runs in the phase where its data exists:

| Phase              | Runs when                         | What becomes visible                               |
| ------------------ | --------------------------------- | -------------------------------------------------- |
| `request_headers`  | The request headers arrive        | Client IP, URI, headers, cookies, query arguments, JWT and schema parameter results |
| `request_body`     | Body inspection finishes          | Raw body, form fields, multipart parts, schema body results |
| `response_headers` | The upstream's headers arrive     | Response status and headers                        |
| `response_body`    | Response body inspection finishes | Response body                                      |
| `logging`          | The request is complete           | Everything collected during the request            |

Request phases can block, challenge or allow; response body rules can suppress or replace a body; the rest observe and score. See [Phases](../../rules/phases/).

## Where it runs

| Host | What you get |
| --- | --- |
| [The `openshield` proxy](../../hosts/pingora-proxy/) | A standalone reverse proxy on Pingora: TLS, keep-alive pools, zero-downtime reloads, Prometheus metrics. |
| [The nginx module](../../hosts/nginx-module/) | The same WAF inside nginx, switched on per location, with shared-memory rate limits across workers. |
| [The library](../../hosts/library/) | `openshield-core`, the engine itself, for embedding in another Rust server. |

The WAF configuration is the same YAML in every host.
