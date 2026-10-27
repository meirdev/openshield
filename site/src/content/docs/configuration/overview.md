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
  path: /dev/stderr
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
        expression: '(http.request.uri.path == "/admin" or starts_with(http.request.uri.path, "/admin/")) and not ip.src in $office'
```

This rule protects both `/admin` and paths below `/admin/`, allowing access only from the `office` list. Replace its example addresses with the ones you intend to allow.

## Loading and validation

The proxy needs only `listen` and `upstream` to start forwarding traffic. To enforce a policy, add active rules to a root ruleset and give them distinct IDs. Rate-limit counters use those IDs, so reusing one can unintentionally share counts.

Relative file paths resolve from the process's working directory. For example, when OpenShield starts in `/srv/app`, `file: ./openapi.yaml` resolves there even if the configuration is in `/etc/openshield`. Use absolute paths or a fixed working directory to keep this predictable.

Before starting, run `openshield --test -c config.yaml` to validate and initialize the WAF without opening a listener. The check opens log files, so their directories must exist and be writable. It rejects unknown keys in `logging`, `audit_log`, and `metrics`, but does not catch every misspelled configuration key. See [Running](../../operations/running/#validate) for the scope of validation.

## Sections

| Section | Keys |
| --- | --- |
| [Proxy](../proxy/) | `listen`, `upstream`, `tls`, `workers`, `upstream_keepalive_pool`, `pid_file`, `upgrade_sock`, `metrics` |
| [Body inspection](../body-inspection/) | `max_request_body_buffer`, `request_body_limit_action`, `inspect_response_body`, `max_response_body_buffer`, `response_body_limit_action` |
| [Logging](../logging/) | `logging`, `audit_log`, `log_payloads`, `detection_only` |
| [Rules](../../rules/rulesets/) | `rulesets`, `lists`, `scores` |
| [Protections](../../protections/injection-detection/) | `geoip`, `challenge`, `token_configurations`, `schemas` |
