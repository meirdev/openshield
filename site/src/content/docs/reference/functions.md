---
title: Functions
description: "Every function available in expressions."
sidebar:
  order: 1
---

Transforms and detection functions accept a string or an array of strings and apply element-wise to arrays; use `[*]` on the argument and `any` or `all` on the result.

## Transforms

| Function | Returns |
| --- | --- |
| `lower(s)`, `upper(s)` | ASCII case conversion |
| `trim(s)`, `trim_start(s)`, `trim_end(s)` | Without surrounding, leading or trailing whitespace |
| `url_decode_uni(s)` | Percent-decoded, including `%uXXXX` |
| `html_entity_decode(s)` | With HTML entities decoded |
| `base64_decode(s)`, `base64_encode(s)` | Base64 decoding and encoding |
| `hex_decode(s)`, `hex_encode(s)` | Hex decoding and encoding |
| `md5(s)`, `sha1(s)` | The hash as a hex string |
| `utf8_to_unicode(s)` | Non-ASCII characters as `\uXXXX` |
| `remove_nulls(s)`, `replace_nulls(s)` | Null bytes removed, or replaced by spaces |
| `remove_whitespace(s)` | Without any ASCII whitespace |
| `compress_whitespace(s)` | Each whitespace run collapsed to one space |
| `replace_comments(s)` | Each `/* … */` replaced by one space |
| `regex_replace(s, "pattern", "replacement")` | All matches replaced; the pattern is compiled once |

## Detection

| Function | Returns |
| --- | --- |
| `detect_sqli(s)` | `true` if the string looks like SQL injection (libinjection) |
| `detect_xss(s)` | `true` if the string looks like cross-site scripting (libinjection) |

## Strings

| Function | Returns |
| --- | --- |
| `len(s)` | Length in bytes |
| `starts_with(s, "prefix")`, `ends_with(s, "suffix")` | Boolean |
| `regex_capture(s, "pattern")` | Array of capture groups; `[0]` is the whole match. The pattern is compiled once |
| `concat(a, b, …)` | The strings joined |

## Aggregation

| Function | Returns |
| --- | --- |
| `any(array)` | `true` if any element is `true` |
| `all(array)` | `true` if every element is `true` |

## Maps and arrays

| Function | Returns |
| --- | --- |
| `has_key(map, "key")` | Whether the map has the key |
| `has_value(collection, value)` | Whether the value occurs in the array, or in any of the map's values |
| `except(map, "key", …)` | The map without those keys |
| `except_matching(map, "regex", …)` | The map without the keys matching any pattern |

```text
# A body parameter that is not one of the declared ones
len(except(http.request.body.form, "user", "password").names) > 0
```

## JSON

| Function | Returns |
| --- | --- |
| `lookup_json_string(s, key, …)` | The value at the key path as a string; invalid JSON or a missing path gives `""` |
| `lookup_json_integer(s, key, …)` | The integer at the key path; only plain integers count (`42.0` and `"42"` do not), and anything else leaves the value absent |

Keys are string literals for objects and integer literals for array indexes:

```text
lookup_json_string(http.request.body.raw, "users", 0, "name") == "alice"
lookup_json_integer(http.request.body.raw, "quantity") > 1000
```

## JWT

| Function | Returns |
| --- | --- |
| `is_jwt_valid("id")` | Whether the request carries a valid token for the token configuration |
| `is_jwt_present("id")` | Whether any token source has a value |

See [JWT validation](../../protections/jwt-validation/).
