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

The proxy uses an async runtime in one process with `workers` threads, defaulting to one per CPU. It accepts HTTP/1.1 and HTTP/2 from clients and uses pooled HTTP/1.1 connections to the upstream, without creating a thread or process for each connection.

When `request_body` rules are configured, the proxy holds body data until end of stream or a partial-inspection decision. Otherwise, it streams the body while the core retains a capped copy. A request-phase block sends the rule's status, content type, and body; a response-body block can replace only the remaining body.

During a [graceful reload](../../operations/running/#reload), a replacement process takes over the listening sockets. Validate the configuration first, since the handoff does not check whether the replacement is ready before signaling the old process.

Its settings are the [proxy settings](../../configuration/proxy/). Everything else in the file is the WAF configuration, which the [nginx module](../nginx-module/) reads unchanged.
