---
title: Introduction
description: "What OpenShield is, how a request moves through it, and where it runs."
sidebar:
  order: 1
---

OpenShield is a web application firewall written in Rust that inspects HTTP traffic using rules you write in [Wirefilter](https://github.com/cloudflare/wirefilter). You can run the same engine as a [Pingora proxy](../../hosts/pingora-proxy/), an [nginx module](../../hosts/nginx-module/), or a [Rust library](../../hosts/library/).

Because no attack-blocking policy is enabled by default, you choose what to inspect and how to respond. [Installation](../installation/) and [Your first configuration](../first-configuration/) take you from a binary to a working blocking rule.

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

Added to a proxy configuration with `listen` and `upstream`, this rule blocks when any decoded query argument triggers SQL injection detection. The query **field** supplies the values, the **functions** decode and inspect them, and the **expression** combines the results into a match. The `block` **action** determines what happens next.

## Detections become fields, rules decide

Use these capabilities together in a policy:

- **Injection detection** with libinjection, behind transforms that undo the encodings attackers use.
- **JWT validation** against keys you configure, with the token's claims exposed as fields.
- **Schema validation** of requests against an OpenAPI document, with every violation exposed as fields.
- **GeoIP**, **IP and string lists**, **per-request scores** and **rate limits** by any combination of fields.
- **Turnstile challenges** for suspicious clients.

JWT validation, schema validation, and GeoIP populate fields that your rules can use to decide whether to block. Injection detection contributes to the same policy through functions called directly in expressions, so you can combine several signals in one rule.

## Five phases

Use the earliest phase with the data your rule needs:

| Phase              | Runs when                         | What becomes visible                                                                |
| ------------------ | --------------------------------- | ----------------------------------------------------------------------------------- |
| `request_headers`  | The request headers arrive        | Client IP, URI, headers, cookies, query arguments, JWT and schema parameter results |
| `request_body`     | Body inspection finishes          | Raw body, form fields, multipart parts, schema body results                         |
| `response_headers` | The upstream's headers arrive     | Response status and headers                                                         |
| `response_body`    | Response body inspection finishes | Response body                                                                       |
| `logging`          | The request is complete           | Everything collected during the request                                             |

The phase also determines what a rule can do. Request phases can block or allow traffic, with challenges available in `request_headers`; response-body rules can replace a body after its headers have been sent. See [Phases](../../rules/phases/) for ordering and enforcement limits.

## Where it runs

| Host                                                 | What you get                                                                                                |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [The `openshield` proxy](../../hosts/pingora-proxy/) | A standalone reverse proxy on Pingora: TLS, keep-alive pools, graceful process reloads, Prometheus metrics. |
| [The nginx module](../../hosts/nginx-module/)        | The same WAF inside nginx, switched on per location, with shared-memory rate limits across workers.         |
| [The library](../../hosts/library/)                  | `openshield-core`, the engine itself, for embedding in another Rust server.                                 |

The WAF settings are shared across all three hosts, while each host supplies its own listener, TLS, upstream, and access-log configuration.
