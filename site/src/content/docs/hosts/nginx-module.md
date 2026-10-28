---
title: nginx module
description: "The same WAF as a dynamic nginx module, switched on per location."
sidebar:
  order: 2
---

`libopenshield_nginx.so` runs the WAF inside nginx. The module loads a WAF configuration when nginx reads its own, and inspects requests on the locations where it is switched on.

The following HTTP configuration enables inspection in front of an application listening on port 3000:

```nginx
load_module modules/libopenshield_nginx.so;

events {}

http {
    openshield_config /etc/openshield/waf.yaml;

    log_format waf '$remote_addr "$request" $status $openshield_action $openshield_rules $openshield_request_id';
    access_log /var/log/nginx/access.log waf;

    server {
        listen 8080;

        location / {
            openshield on;
            proxy_pass http://127.0.0.1:3000;
        }

        location /static/ {
            openshield off;
            proxy_pass http://127.0.0.1:3000;
        }
    }
}
```

The YAML holds the [WAF keys](../../configuration/overview/) only, not the proxy's `listen`, `upstream`, `tls`, `logging` or `metrics`; nginx provides those. The audit log is written by the WAF to `audit_log.path`; set a file, since the default `/dev/stderr` lands in nginx's error log.

## Directives

| Directive                             | Context                      | Description                                                                                       |
| ------------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------- |
| `openshield_config` _path_            | `http`                       | The WAF configuration file. Relative paths resolve from nginx's prefix. Errors fail `nginx -t`    |
| `openshield on` \| `off`              | `http`, `server`, `location` | Inspect requests here; inherited by nested blocks, off by default                                 |
| `openshield_turnstile_location` _uri_ | `http`                       | Internal location proxying Turnstile verification to Cloudflare; default `/_openshield/turnstile` |
| `openshield_ratelimit_zone` _size_    | `http`                       | Shared memory for rate-limit counters, default `10m`; a counter takes under 100 bytes             |

Validate changes with `nginx -t` before applying them with `nginx -s reload`. The reload rebuilds the WAF while preserving shared rate-limit counters if the zone size is unchanged. When the zone fills, it evicts counters that have been idle for two periods and have no active mitigation; if none qualify, the request passes and a warning is logged.

## Variables

After inspection, these variables expose the result to `log_format`. Locations with `openshield off` leave them unset, so nginx logs them as `-`.

| Variable                 | Value                                                               |
| ------------------------ | ------------------------------------------------------------------- |
| `$openshield_action`     | `pass`, `allow`, `block` or `challenge`                             |
| `$openshield_rules`      | IDs of the rules that matched with logging enabled, comma-separated |
| `$openshield_request_id` | The ID of the audit record                                          |

## What runs where

| OpenShield phase   | nginx phase   | Notes                                                                                         |
| ------------------ | ------------- | --------------------------------------------------------------------------------------------- |
| `request_headers`  | access        | Blocks are answered with the rule's status, content type and body; challenge pages are served |
| `request_body`     | access        | With `request_body` rules, the body is read before proxying and inspected                     |
| `response_headers` | header filter | Side effects only: scores and logging                                                         |
| `response_body`    | body filter   | With `inspect_response_body: true`; a block replaces the rest of the body                     |
| `logging`          | log           | Before nginx writes the access log, so the variables are filled                               |

Only the main request is inspected; subrequests and `error_page` redirects reuse its verdict. The filters sit at the top of nginx's chains and see the upstream response before `gzip` and the other output filters. While a response body is inspected its buffers are copied once; with `inspect_response_body` off responses are untouched. With `response_body` rules, `Content-Length` is dropped from inspected responses so nginx can re-frame a body that was held or replaced.

Request bodies are read only when the configuration has `request_body` rules, then in full before proxying, as nginx does unless `proxy_request_buffering` is off. `client_max_body_size` applies first and rejects oversized bodies with `413`. Bodies larger than `client_body_buffer_size` are spilled to a temporary file and read back; set it to at least `max_request_body_buffer` to avoid the extra I/O.

## Challenges

Verifying a Turnstile token means asking Cloudflare, which the module does without blocking a worker: an in-memory subrequest to an internal location that proxies to Cloudflare. Define it in the server that serves challenged paths:

```nginx
location = /_openshield/turnstile {
    internal;
    proxy_pass https://challenges.cloudflare.com/turnstile/v0/siteverify;
    proxy_ssl_server_name on;
    proxy_set_header Host challenges.cloudflare.com;
}
```

Name it with `openshield_turnstile_location` if you use another URI. The rest of the flow is as in the proxy.

## Building

The module must be built against the nginx it will load into: nginx's `configure` flags and distribution patches shape the ABI. You need a Rust toolchain, a C compiler, `libclang` for the binding generator, and nginx's build dependencies (OpenSSL, PCRE2 and zlib headers).

For production, configure the matching nginx source tree before building the module against it:

```bash
tar xf nginx-1.28.3.tar.gz && cd nginx-1.28.3
./configure --with-compat <the flags of your nginx build>
cd -
NGINX_BUILD_DIR=$PWD/nginx-1.28.3/objs cargo build --release -p openshield-nginx
```

`nginx -V` prints an installed nginx's flags. The module is at `target/release/libopenshield_nginx.so`; copy it to nginx's modules directory.

For development and tests, the `vendored` feature builds a bundled nginx instead:

```bash
make nginx        # cargo build -p openshield-nginx --features vendored
make nginx-test   # builds, then cargo test -p openshield-nginx --features vendored
```

The test loads the module into that nginx in front of an echo server. Build before testing: `cargo test` does not rebuild a cdylib, and the test refuses a module older than its sources. `OPENSHIELD_NGINX_BIN` points the test at another nginx binary. The module is a workspace member but not a default member, so `cargo build` and `cargo test` at the repository root leave it out.
