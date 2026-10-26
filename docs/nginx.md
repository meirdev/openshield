# nginx module

OpenShield runs inside nginx as a dynamic module, `libopenshield_nginx.so`, built from `crates/openshield-nginx`. The module loads a WAF configuration once, when nginx reads its own configuration, and inspects requests on the locations where it is switched on.

```nginx
load_module modules/libopenshield_nginx.so;

http {
    openshield_config /etc/openshield/waf.yaml;

    log_format waf '$remote_addr "$request" $status $openshield_action $openshield_rules $openshield_request_id';

    access_log /var/log/nginx/access.log waf;

    server {
        listen 443 ssl;

        location / {
            openshield on;
            proxy_pass http://backend;
        }

        location /static/ {
            openshield off;
        }
    }
}
```

## Directives

| Directive                           | Context                      | Description                                                                                                                                                                       |
| ----------------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `openshield_config` path            | `http`                       | The WAF configuration: a YAML file with the WAF keys from [configuration](configuration.md) and nothing else. Relative paths resolve from nginx's prefix. Errors fail `nginx -t`. |
| `openshield on` \| `off`            | `http`, `server`, `location` | Inspect requests here. Inherited by nested blocks; defaults to off.                                                                                                               |
| `openshield_turnstile_location` uri | `http`                       | Internal location that proxies Turnstile verification to Cloudflare; see [Challenges](#challenges). Default `/_openshield/turnstile`.                                             |
| `openshield_ratelimit_zone` size    | `http`                       | Shared memory for rate-limit counters, such as `10m` (the default). Each counter takes under 100 bytes.                                                                           |

`nginx -s reload` rebuilds the WAF from the file. Rate-limit counters live in a shared memory zone, so all worker processes count together, and they survive a reload as long as the zone's size is unchanged. When the zone is full, counters that have not been seen for two periods are dropped; if none can be dropped, the request is let through and a warning is logged.

## Variables

Set once the request has been inspected, so they are meant for `log_format`. Requests on locations with `openshield off` leave them unset, which nginx logs as `-`.

| Variable                 | Value                                                               |
| ------------------------ | ------------------------------------------------------------------- |
| `$openshield_action`     | `pass`, `allow`, `block` or `challenge`                             |
| `$openshield_rules`      | IDs of the rules that matched with logging enabled, comma-separated |
| `$openshield_request_id` | The ID used in the audit log entry                                  |

The audit log is written by the WAF itself to the `audit_log` path in the YAML. With the default `/dev/stderr` it lands in nginx's error log, so set a file path.

## What runs where

| OpenShield phase   | nginx phase   | Status                                                                                                                    |
| ------------------ | ------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `request_headers`  | access        | Done. Block responses are sent with the rule's status, content type and body. Challenge pages are served.                 |
| `request_body`     | access        | Done. When `request_body` rules exist, the body is read before proxying and inspected.                                    |
| `response_headers` | header filter | Done, for its side effects (scores, logging). A block verdict here is not acted on.                                       |
| `response_body`    | body filter   | Done, with `inspect_response_body: true`. A block replaces the rest of the body; the status and headers are already sent. |
| `logging`          | log           | Done. Runs before nginx writes the access log, so the variables are filled.                                               |

Only the main request is inspected. Subrequests and `error_page` redirects reuse its verdict.

The filters sit at the top of nginx's chains, so they see the upstream response before `gzip` and the other output filters. While a response body is inspected, its buffers are copied once on the way through; responses are untouched when `inspect_response_body` is off. When `response_body` rules exist, `Content-Length` is dropped from inspected responses so nginx can re-frame a body that was held or replaced.

Request bodies are read only when the configuration has `request_body` rules, and then in full before the request is proxied, as nginx does anyway unless `proxy_request_buffering` is off. nginx's `client_max_body_size` still applies first and rejects oversized bodies with `413`. Bodies larger than `client_body_buffer_size` are spilled to a temp file and read back for inspection; set it to at least the WAF's `max_request_body_buffer` to avoid the extra I/O.

## Challenges

Rules with `action: challenge` serve the Turnstile page as in the proxy. Verifying the token the page posts back means asking Cloudflare, which the module does without blocking a worker: it issues an in-memory subrequest to an internal location that proxies to Cloudflare's endpoint. Define that location in the server that serves challenged paths:

```nginx
location = /_openshield/turnstile {
    internal;
    proxy_pass https://challenges.cloudflare.com/turnstile/v0/siteverify;
    proxy_ssl_server_name on;
    proxy_set_header Host challenges.cloudflare.com;
}
```

Name it with `openshield_turnstile_location` if you use another URI. A verified visitor gets the challenge cookie and a redirect back to the page they asked for, exactly as with the proxy; a rejected token gets the page again. Cloudflare's answer is read in memory, so `subrequest_output_buffer_size` needs no change.

## Building

The module must be built against the nginx it will load into, because nginx's `configure` flags and the distribution's patches shape the ABI. Requirements: a Rust toolchain, a C compiler, `libclang` for the binding generator, and the nginx build dependencies (OpenSSL, PCRE2, zlib headers).

Against a configured nginx source tree, which is the production path:

```bash
tar xf nginx-1.28.3.tar.gz && cd nginx-1.28.3
./configure --with-compat <the flags of your nginx build>
cd -
NGINX_BUILD_DIR=$PWD/nginx-1.28.3/objs cargo build --release -p openshield-nginx
```

`nginx -V` prints the flags of an installed nginx. The module is at `target/release/libopenshield_nginx.so`; copy it to nginx's modules directory.

For development and tests, the `vendored` feature builds a bundled copy of nginx instead:

```bash
make nginx        # cargo build -p openshield-nginx --features vendored
make nginx-test   # builds, then cargo test -p openshield-nginx --features vendored
```

The test loads the built module into that nginx in front of an echo server. Build before testing: `cargo test` does not rebuild a cdylib, and the test refuses to run a module older than its sources. To test against another nginx binary, set `OPENSHIELD_NGINX_BIN`.

The module is a workspace member but not a default member, so `cargo build` and `cargo test` at the repository root leave it out.
