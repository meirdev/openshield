---
title: Rules and rulesets
description: "How rules are written, grouped into rulesets, and run or reused with execute."
sidebar:
  order: 1
---

A rule is an `id`, an `action` and an `expression`. Rules live in rulesets; a ruleset with `kind: root` runs on every request, in the order written:

```yaml
rulesets:
  - name: main
    kind: root
    rules:
      - id: block-admin
        phase: request_headers
        action: block
        expression: 'http.request.uri.path == "/admin"'
```

## A rule

| Field                           | Default           | Description                                                                             |
| ------------------------------- | ----------------- | --------------------------------------------------------------------------------------- |
| `id`                            | Required          | Identifies the rule in logs and rate-limit counters; use distinct IDs                   |
| `action`                        | Required          | What to do on a match; see [Actions](../actions/)                                       |
| `expression`                    | Required          | A [Wirefilter expression](../expressions/)                                              |
| `phase`                         | `request_headers` | When the rule runs; see [Phases](../phases/)                                            |
| `action_parameters`             | Omitted           | Details for the action: the block response, scores to add, the ruleset to execute       |
| `ratelimit`                     | Omitted           | Count matches per key and act only past a limit; see [Rate limiting](../rate-limiting/) |
| `logging.enabled`               | `true`            | Record matches in the audit log                                                         |
| `enabled`                       | `true`            | `false` skips the rule                                                                  |
| `categories`                    | `[]`              | Tags that `execute` overrides can target                                                |
| `description`, `ref`, `version` | Omitted           | Documentation: free text, an external reference such as a URL, a version                |

## Rulesets

| `kind`    | Runs                                                                               |
| --------- | ---------------------------------------------------------------------------------- |
| `root`    | On every request, in configuration order                                           |
| `custom`  | Only when a root rule executes it. The default                                     |
| `managed` | Same as `custom`; marks rulesets maintained elsewhere, such as a vendored rule set |

Give each ruleset a unique name so `execute` can refer to it unambiguously; `description` and `version` are optional metadata.

## Executing a ruleset

A root rule with `action: execute` includes the ruleset named in `action_parameters.id`. At configuration load time, its rules are expanded in place, each keeping its own phase. This WAF fragment includes the list used by the guard expression:

```yaml
lists:
  - name: office
    kind: ip
    items: ["203.0.113.0/24"]

rulesets:
  - name: detections
    description: Shared detection rules
    version: "1.0.0"
    rules:
      - id: sqli-args
        categories: [sqli]
        action: block
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
      - id: xss-args
        categories: [xss]
        action: block
        expression: "any(detect_xss(url_decode_uni(http.request.uri.args.values[*])))"

  - name: main
    kind: root
    rules:
      - id: block-admin
        action: block
        expression: 'http.request.uri.path == "/admin"'
      - id: run-detections
        action: execute
        expression: "not ip.src in $office"
        action_parameters:
          id: detections
```

The `execute` expression becomes a guard on every included rule, so a rule from `detections` matches only when both expressions are true. Each guard is evaluated in its child's phase rather than remembered across phases, which means its fields must be available wherever the child runs. Use `expression: "true"` when no guard is needed.

Only root rulesets contain `execute` rules, and they execute custom and managed rulesets only. A ruleset nothing executes never runs; OpenShield warns about it at startup.

### Overrides

Change what an executed ruleset does without editing it:

```yaml
action_parameters:
  id: detections
  overrides:
    action: log # every rule
    enabled: true
    categories:
      - category: sqli
        action: block
    rules:
      - id: xss-args
        enabled: false
```

Rule overrides beat category overrides, which beat the top-level `action` and `enabled`; each level changes only what it sets. When several categories match a rule, the later entry wins.

Overrides are validated: a rule ID or category must exist in the ruleset, overriding to `score` requires the rule to have score parameters, overriding to `challenge` requires a `challenge` block, and `execute` is not allowed as an override action.
