<div align="center">
  <img src="./assets/logo.png" alt="OpenShield Logo" width="500"/>
</div>

OpenShield is a reverse proxy and Web Application Firewall (WAF) built on [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [Wirefilter](https://github.com/cloudflare/wirefilter).

## Repository layout

- `crates/openshield-openapi`: a standalone validator of HTTP requests against OpenAPI 3.0 and 3.1 documents. Usable without the rest of OpenShield.
- `crates/openshield-core`: the WAF engine as a library. A host builds a `Waf` from the config, starts a `Transaction` per request, feeds it headers and body chunks phase by phase, and acts on the verdicts it returns.
- `crates/openshield-pingora`: the `openshield` reverse-proxy binary built on Pingora, which drives the core.
- `crates/openshield-nginx`: the same WAF as an nginx dynamic module.

## Features

- Rules for request and response headers and bodies
- SQL injection and XSS detection with libinjection
- GeoIP lookups, IP and string lists, and threat scores
- Per-key rate limits and Turnstile challenges
- JWT validation with claims available to rules
- OpenAPI schema validation with violation details available to rules
- JSON or text logs and Prometheus metrics

## Quick start

Build with a Rust toolchain that supports edition 2024:

```bash
cargo build --release
```

Create `config.yaml`. Set `upstream` to the address of your application:

```yaml
listen: "127.0.0.1:8080"
upstream: "http://127.0.0.1:3000"
rulesets:
  - name: main
    kind: root
    rules:
      - id: block-sqli
        action: block
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
```

Check the configuration, then start the proxy:

```bash
./target/release/openshield --test -c config.yaml
./target/release/openshield -c config.yaml
```

Send requests to `http://127.0.0.1:8080`. This rule returns `403` when it detects SQL injection in a query argument. Other requests are forwarded to your application.

For a configuration that uses every feature, with an application to run it against, see [examples/](examples/).

## Documentation

The documentation lives at [meirdev.github.io/openshield](https://meirdev.github.io/openshield/). To run it locally, with [bun](https://bun.sh) installed:

```bash
cd site
bun install
bun run dev
```

Then open `http://localhost:4321/`.
