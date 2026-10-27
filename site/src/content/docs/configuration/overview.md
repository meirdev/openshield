---
title: Overview
description: "One YAML file configures the proxy and the WAF. Here is how it is organized."
sidebar:
  order: 1
---

OpenShield reads one YAML file, `config.yaml` or the file given with `-c`. Two groups of keys live in it:

- **Server keys** belong to the host: where to listen, where the application is, TLS, worker threads, logs and metrics. They differ between the [proxy](../proxy/) and the [nginx module](../../hosts/nginx-module/), which takes them from nginx's own configuration.
- **WAF keys** describe what to inspect and how: body limits, the audit log, lists, scores, GeoIP, challenges, token configurations, schemas and rulesets. They are the same in every host.

```yaml
# Server
listen: "127.0.0.1:8080"
upstream: "http://127.0.0.1:3000"
logging:
  format: json
  access_log: /dev/stdout

# WAF
audit_log:
  path: /var/log/openshield/audit.log
lists:
  - name: office
    kind: ip
    items: ["203.0.113.0/24"]
rulesets:
  - name: main
    kind: root
    rules:
      - id: office-only-admin
        action: block
        expression: 'starts_with(http.request.uri.path, "/admin/") and not ip.src in $office'
```

## Rules of thumb

- Only `listen` and `upstream` are required. Without a root ruleset, every request is forwarded uninspected.
- Relative file paths resolve from the directory where OpenShield starts.
- Unknown keys inside `logging`, `audit_log` and `metrics` are errors, so a typo cannot silently disable something.
- Names must be unique within their kind: rulesets, rule IDs within a ruleset, lists, token configurations, schemas.
- `openshield --test -c config.yaml` validates everything, including rule expressions, keys and schemas, without starting the proxy.

## Sections

| Section | Keys |
| --- | --- |
| [Proxy](../proxy/) | `listen`, `upstream`, `tls`, `workers`, `upstream_keepalive_pool`, `pid_file`, `upgrade_sock`, `metrics` |
| [Body inspection](../body-inspection/) | `max_request_body_buffer`, `request_body_limit_action`, `inspect_response_body`, `max_response_body_buffer`, `response_body_limit_action` |
| [Logging](../logging/) | `logging`, `audit_log`, `log_payloads`, `detection_only` |
| [Rules](../../rules/rulesets/) | `rulesets`, `lists`, `scores` |
| [Protections](../../protections/injection-detection/) | `geoip`, `challenge`, `token_configurations`, `schemas` |
