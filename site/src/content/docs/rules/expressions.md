---
title: Expressions
description: "The Wirefilter expression language: comparisons, lists, arrays, maps and functions."
sidebar:
  order: 4
---

Expressions use [Wirefilter](https://github.com/cloudflare/wirefilter), the language of Cloudflare's firewall rules. An expression combines **fields**, **literals**, **functions** and **operators** into a boolean.

```text
http.request.method == "POST" and not ip.src in $office
```

## Comparisons

| Operator | Meaning | Example |
| --- | --- | --- |
| `==`, `!=` | Equal, not equal | `http.request.method == "POST"` |
| `<`, `<=`, `>`, `>=` | Numeric order | `http.response.code >= 500` |
| `contains` | Substring | `http.request.uri.path contains "/admin"` |
| `matches` or `~` | Regular expression | `http.request.uri.path matches "\\.(php|asp)$"` |
| `in` | Membership in a set or list | `http.request.method in {"PUT" "DELETE"}`, `ip.src in $office` |
| `and`, `or`, `not`, `xor` | Boolean logic; parentheses group | `(a or b) and not c` |

Strings are double-quoted; inside YAML, wrap the expression in single quotes. Integers are plain, IPs and CIDRs are plain too: `ip.src in {10.0.0.0/8 192.168.1.1}`. Set literals use spaces between items.

## Absent fields

A field with no value, such as `http.request.body.raw` before the body phase or `ip.src.country` without GeoIP, makes any comparison on it false, and `not` of that true. Write conditions as things that must hold: `not any(http.request.jwt.claims.aud["api"][*] == "admin")` blocks both tokens with the wrong audience and requests without a token.

## Arrays and maps

Headers, cookies, query arguments and form fields are maps from name to an array of values, because a name can repeat:

```text
http.request.headers["content-type"][0] == "application/json"
http.request.uri.args["id"][0] == "42"
any(http.request.cookies["session"][*] == "")
```

`[*]` applies the rest of the expression to every element, and `any` or `all` folds the results. Functions apply element-wise too:

```text
any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))
all(len(http.request.headers.values[*]) < 4096)
```

Header names are lowercase; cookie and argument names keep their case. Every map has `.names` and `.values` arrays alongside it.

## Functions

Functions transform values (`lower`, `url_decode_uni`), detect attacks (`detect_sqli`, `detect_xss`), inspect strings (`starts_with`, `regex_capture`) and ask about detections (`is_jwt_valid`). Nest them freely:

```text
detect_xss(html_entity_decode(url_decode_uni(http.request.uri.query)))
regex_capture(http.request.uri.path, "/item/(\\d+)")[1] == "42"
lookup_json_string(http.request.body.raw, "user", "role") == "admin"
```

The full list is in the [Functions reference](../../reference/functions/); the fields in the [Fields reference](../../reference/fields/).

## Lists

`$name` refers to a configured [list](../lists/): `ip.src in $office`, `http.user_agent in $scanner_ua`.
