<div align="center">
  <img src="./assets/logo.png" alt="OpenShield Logo" width="500"/>
</div>

OpenShield is a reverse proxy and Web Application Firewall (WAF) built on [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [Wirefilter](https://github.com/cloudflare/wirefilter).

## Features

- Rules for request and response headers and bodies
- SQL injection and XSS detection with libinjection
- GeoIP lookups, IP and string lists, and threat scores
- Per-key rate limits and Turnstile challenges
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

## Documentation

- [Configuration](docs/configuration.md): settings, defaults, and optional services
- [Rules](docs/rules.md): phases, actions, rate limits, functions, and fields
- [Turnstile challenges](docs/challenges.md): verification flow and custom pages
- [Operations](docs/operations.md): reloads, logging, and metrics
