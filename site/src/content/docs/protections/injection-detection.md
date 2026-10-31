---
title: Injection detection
description: "Detect SQL injection and XSS, normalize inputs, and combine signals with scores."
sidebar:
  order: 1
---

`detect_sqli` follows [libinjection](https://github.com/libinjection/libinjection)'s method: it tokenizes the string as SQL in the contexts a query could splice it into (bare, or inside a single- or double-quoted string), folds the tokens down to their structure and looks the resulting fingerprint up in a database of shapes seen in attacks. `detect_xss` uses OpenShield's own detector: it tokenizes the string as HTML in every context a page could reflect it into (text, or inside an attribute value with any quoting) and flags markup that would execute, such as script-bearing tags, event handler attributes, `javascript:` URLs, executable style constructs and dangling-markup exfiltration. It does not flag inline styles or unknown tags on their own. Use `[*]` to check each array element:

```text
any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))
any(detect_xss(url_decode_uni(http.request.body.form.values[*])))
detect_sqli(lookup_json_string(http.request.body.raw, "query"))
```

## Decode before detecting

Attackers encode payloads so a naive filter does not see them. Apply the transforms the application will apply, innermost first:

| Transform                                                                      | Undoes                                                         |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| `url_decode_uni`                                                               | Percent-encoding, including `%uXXXX`                           |
| `html_entity_decode`                                                           | `&lt;`, `&#x3c;` and friends                                   |
| `base64_decode`, `hex_decode`                                                  | Encoded parameters                                             |
| `lower`                                                                        | Case variations                                                |
| `compress_whitespace`, `remove_whitespace`, `replace_comments`, `remove_nulls` | Padding, `/**/` comments and null bytes used to split keywords |

```text
detect_xss(html_entity_decode(url_decode_uni(http.request.uri.query)))
```

Query arguments and form fields are already decoded once when they are parsed into maps; decoding again handles double encoding.

## Where to look

| Source              | Field                                                                                                       |
| ------------------- | ----------------------------------------------------------------------------------------------------------- |
| Query arguments     | `http.request.uri.args.values[*]`, or the raw `http.request.uri.query`                                      |
| Form fields         | `http.request.body.form.values[*]` (`request_body` phase)                                                   |
| Multipart fields    | `http.request.body.multipart.values[*]`                                                                     |
| JSON bodies         | `lookup_json_string(http.request.body.raw, "key", …)` for known keys, or `http.request.body.raw` as a whole |
| Cookies and headers | `http.request.cookies.values[*]`, `http.request.headers.values[*]`                                          |
| Path                | `http.request.uri.path`                                                                                     |

## Score, then decide

Scoring lets you assign different weights to detection sources before deciding whether to block. In this example, a query-argument match contributes enough points to reach the threshold by itself, while a user-agent match needs another signal:

```yaml
scores: [sqli]
rulesets:
  - name: main
    kind: root
    rules:
      - id: sqli-args
        action: score
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
        action_parameters: { scores: [{ name: sqli, increment: 10 }] }
      - id: sqli-ua
        action: score
        expression: "detect_sqli(http.user_agent)"
        action_parameters: { scores: [{ name: sqli, increment: 3 }] }
      - id: block-sqli
        phase: request_body
        action: block
        expression: "score.sqli >= 10"
```

Since detectors can miss attacks or flag benign input, review representative traffic with `detection_only: true` before enforcing the policy. If you need the matching field values to investigate a result, enable `log_payloads` after reviewing what the audit log [captures](../../configuration/logging/#captured-data). At `debug` log level, both functions also log why they matched, for example `detect_xss: onerror attribute in text context` or `detect_sqli: s&sos fingerprint in single-quoted context`.
