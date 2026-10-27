---
title: Your first configuration
description: "Put OpenShield in front of an application and block your first attack in five minutes."
sidebar:
  order: 3
---

This walkthrough starts a proxy in front of an application, adds a rule, and checks that it fires. It assumes an application listening on `127.0.0.1:3000`; any HTTP server does, including `python3 -m http.server 3000`.

## 1. Write `config.yaml`

Only `listen` and `upstream` are required:

```yaml
listen: "127.0.0.1:8080"
upstream: "http://127.0.0.1:3000"
```

Check it and start the proxy:

```bash
openshield --test -c config.yaml
openshield -c config.yaml
```

Requests to `http://127.0.0.1:8080` are now forwarded to your application. Without rules, nothing is inspected yet; each request is written to the access log on stdout.

## 2. Add a rule

Rules live in rulesets. A ruleset with `kind: root` runs on every request:

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

Restart the proxy and try an injection:

```bash
curl -i "http://127.0.0.1:8080/search?q=1'%20OR%20'1'='1"
```

The response is `403 Forbidden` from OpenShield, and the audit log on stderr records which rule matched:

```json
{"request_id":"…","waf_action":"block","waf_matched_rules":[{"id":"block-sqli","action":"block"}],"request":{"path":"/search","query":"q=1'%20OR%20'1'='1", …}}
```

A benign request still reaches the application:

```bash
curl -i "http://127.0.0.1:8080/search?q=cats"
```

## 3. Decide what a block looks like

Blocks return `403` with an empty body by default. Give the rule its own response:

```yaml
      - id: block-sqli
        action: block
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
        action_parameters:
          response:
            status_code: 400
            content_type: application/json
            content: '{"error": "request rejected"}'
```

## 4. Observe before enforcing

To roll rules out safely, set `detection_only: true` at the top level. Rules evaluate, matches are logged, and nothing is blocked or challenged. Turn it off when the audit log shows what you expect.

## Where to go next

- The [example](../example/) has a configuration that uses every feature and an application to run it against.
- [Rules](../../rules/rulesets/) explains rulesets, phases, actions and expressions.
- [Configuration](../../configuration/overview/) lists every setting.
