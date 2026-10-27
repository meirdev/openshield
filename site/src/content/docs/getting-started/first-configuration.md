---
title: Your first configuration
description: "Start a local proxy, block a SQL injection attempt, and verify the result."
sidebar:
  order: 3
---

This walkthrough uses [OpenShield](../installation/), Python 3, and `curl` to put a firewall in front of a local server. Run the configuration commands from the directory containing `config.yaml`, using the binary's full path if `openshield` is not on your `PATH`.

## 1. Write `config.yaml`

In one terminal, start a local application:

```bash
python3 -m http.server 3000 --bind 127.0.0.1
```

Create `config.yaml` with the two required proxy settings:

```yaml
listen: "127.0.0.1:8080"
upstream: "http://127.0.0.1:3000"
```

Validate it, then start OpenShield in a second terminal:

```bash
openshield --test -c config.yaml
openshield -c config.yaml
```

Once the proxy is running, send a request from a third terminal:

```bash
curl -i http://127.0.0.1:8080/
```

You should receive `200 OK` and the Python server's directory listing, since the proxy is forwarding traffic without any WAF rules yet.

## 2. Add a rule

To add SQL injection detection, stop OpenShield with `Ctrl+C` and replace `config.yaml` with this configuration:

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

The root ruleset runs automatically and blocks when any query argument triggers the detector. Validate the updated file and restart the proxy to apply it:

```bash
openshield --test -c config.yaml
openshield -c config.yaml
```

Compare ordinary input with an injection attempt:

```bash
# Forwarded: 200
curl -i "http://127.0.0.1:8080/?q=cats"

# Blocked: 403
curl -i --get --data-urlencode "q=1' OR '1'='1" http://127.0.0.1:8080/
```

The blocked response has an empty body. Its audit record on stderr includes:

```json
{
  "waf_action": "block",
  "waf_matched_rules": [{"id": "block-sqli", "action": "block"}]
}
```

Both requests appear in the access log; only the matching request produces an audit record.

## 3. Decide what a block looks like

Replace the rule under `rules:` with this version:

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

After validating the file and restarting the proxy, repeat the injection request. It should now return `400` with your JSON body.

## 4. Observe before enforcing

To see what a rule would block while still forwarding requests, add this top-level setting, then validate and restart:

```yaml
detection_only: true
```

The injection request now reaches the application, though its audit record still says `waf_action: block`. That value records the rule's decision; the access log's `status` shows the response actually sent. See [detection-only behavior](../../configuration/logging/#detection-only-mode) for how other rules and limits are affected.

When you are ready to enforce the policy, set `detection_only: false`, validate, and restart. You can stop both local servers with `Ctrl+C` when finished.

## Where to go next

Try [the example](../example/) to explore more protections, or read [Rules and rulesets](../../rules/rulesets/) to learn how policies are ordered and reused. When you are ready to operate the proxy, [Running](../../operations/running/) covers validation and reloads.
