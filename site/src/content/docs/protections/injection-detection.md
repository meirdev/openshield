---
title: Injection detection
description: "SQL injection and XSS detection with libinjection, and the transforms that defeat evasion."
sidebar:
  order: 1
---

`detect_sqli` and `detect_xss` run [libinjection](https://github.com/libinjection/libinjection), the detector used by ModSecurity and many commercial firewalls. They take a string, or an array of strings, and return whether it looks like an attack.

```text
any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))
any(detect_xss(url_decode_uni(http.request.body.form.values[*])))
detect_sqli(lookup_json_string(http.request.body.raw, "query"))
```

## Decode before detecting

Attackers encode payloads so a naive filter does not see them. Apply the transforms the application will apply, innermost first:

| Transform | Undoes |
| --- | --- |
| `url_decode_uni` | Percent-encoding, including `%uXXXX` |
| `html_entity_decode` | `&lt;`, `&#x3c;` and friends |
| `base64_decode`, `hex_decode` | Encoded parameters |
| `lower` | Case variations |
| `compress_whitespace`, `remove_whitespace`, `replace_comments`, `remove_nulls` | Padding, `/**/` comments and null bytes used to split keywords |

```text
detect_xss(html_entity_decode(url_decode_uni(http.request.uri.query)))
```

Query arguments and form fields are already decoded once when they are parsed into maps; decoding again handles double encoding.

## Where to look

| Source | Field |
| --- | --- |
| Query arguments | `http.request.uri.args.values[*]`, or the raw `http.request.uri.query` |
| Form fields | `http.request.body.form.values[*]` (`request_body` phase) |
| Multipart fields | `http.request.body.multipart.values[*]` |
| JSON bodies | `lookup_json_string(http.request.body.raw, "key", …)` for known keys, or `http.request.body.raw` as a whole |
| Cookies and headers | `http.request.cookies.values[*]`, `http.request.headers.values[*]` |
| Path | `http.request.uri.path` |

## Score, then decide

Detection on every input in one rule blocks on the first hit. Scoring each source separately and deciding on the total keeps a single false positive from blocking a user, and lets you weight sources:

```yaml
scores: [sqli]
rulesets:
  - name: main
    kind: root
    rules:
      - id: sqli-args
        action: score
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
        action_parameters: {scores: [{name: sqli, increment: 10}]}
      - id: sqli-ua
        action: score
        expression: "detect_sqli(http.user_agent)"
        action_parameters: {scores: [{name: sqli, increment: 3}]}
      - id: block-sqli
        phase: request_body
        action: block
        expression: "score.sqli >= 10"
```

Roll out with `detection_only: true` and `log_payloads: true`, read the audit log for a while, then enforce.
