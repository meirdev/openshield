---
title: The proxy
description: "The openshield binary: a reverse proxy on Cloudflare Pingora that hosts the WAF."
sidebar:
  order: 1
---

`openshield` is a reverse proxy built on [Pingora](https://github.com/cloudflare/pingora), the Rust framework that serves Cloudflare's own edge. It terminates TLS, keeps a pool of connections to your application, and runs the WAF on every request.

```text
client ──HTTPS──▶ openshield ──HTTP──▶ application
                  │
                  ├─ request_headers rules
                  ├─ request_body rules       (body buffered when needed)
                  ├─ response_headers rules
                  ├─ response_body rules      (body buffered when enabled)
                  └─ logging rules, access + audit logs
```

- One process, `workers` threads (one per CPU by default), an async runtime: no per-connection processes or threads.
- [Zero-downtime reloads](../../operations/running/#reload): a replacement process takes over the listening sockets.
- HTTP/1.1 and HTTP/2 from clients; HTTP/1.1 to the upstream, with keep-alive pooling.
- Request bodies are only held when `request_body` rules exist, and released as soon as the rules allow; otherwise they stream.
- Block responses are sent with the rule's status, content type and body; a `response_body` block replaces the remaining body.

Its settings are the [proxy settings](../../configuration/proxy/). Everything else in the file is the WAF configuration, which the [nginx module](../nginx-module/) reads unchanged.
