---
title: Functions
description: "Every function available in expressions."
sidebar:
  order: 1
---

Transforms and detectors operate on strings, with `[*]` applying them to each element of an array. You can then combine boolean results with `any` or `all`. For functions that also accept arrays directly, the distinction matters: `len(array)` counts elements, while `len(array[*])` measures each element.

## Transforms

Names and behaviour follow Cloudflare's [rules language functions](https://developers.cloudflare.com/ruleset-engine/rules-language/functions/), with additions for attack detection.

| Function                                     | Returns                                                                                                    |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `lower(s)`, `upper(s)`                       | ASCII case conversion                                                                                      |
| `trim(s)`, `trim_start(s)`, `trim_end(s)`    | Without surrounding, leading or trailing ASCII whitespace                                                  |
| `remove_bytes(s, "bytes")`                   | Every byte that occurs in the literal removed, e.g. `remove_bytes(s, "\x00")` strips null bytes           |
| `url_decode(s)`, `url_decode(s, "options")`  | `%XX` and `+` decoded. Options: `u` also decodes `%uXXXX` to UTF-8, `r` repeats until nothing changes      |
| `html_entity_decode(s)`                      | With HTML entities decoded                                                                                 |
| `decode_base64(s)`, `encode_base64(s)`       | Base64 decoding and encoding                                                                               |
| `hex_decode(s)`, `hex_encode(s)`             | Hex decoding and encoding                                                                                  |
| `md5(s)`, `sha1(s)`, `sha256(s)`, `sha512(s)` | The raw binary digest; wrap in `hex_encode` for hex, e.g. `hex_encode(sha256(s))`                         |
| `regex_replace(s, "pattern", "replacement")` | All matches replaced (Cloudflare replaces only the first); the pattern is compiled once                    |

## Detection

| Function         | Returns                                                             |
| ---------------- | ------------------------------------------------------------------- |
| `detect_sqli(s)` | `true` if the string would change the meaning of an SQL query       |
| `detect_xss(s)`  | `true` if the string would execute if reflected into HTML           |

## Strings

| Function                                             | Returns                                                                         |
| ---------------------------------------------------- | ------------------------------------------------------------------------------- |
| `len(s)`, `len(array)`                               | String length in bytes, or number of array elements                             |
| `starts_with(s, "prefix")`, `ends_with(s, "suffix")` | Boolean                                                                         |
| `regex_capture(s, "pattern")`                        | Array of capture groups; `[0]` is the whole match. The pattern is compiled once |
| `concat(a, b, …)`                                    | The strings joined                                                              |
| `split(s, "separator", limit)`                       | Array of at most `limit` parts (1–128); the last part keeps the remainder       |
| `join(array, "separator")`                           | The array's strings joined with the separator; the inverse of `split`           |

## Aggregation

| Function     | Returns                           |
| ------------ | --------------------------------- |
| `any(array)` | `true` if any element is `true`   |
| `all(array)` | `true` if every element is `true` |

## Maps and arrays

| Function                           | Returns                                                              |
| ---------------------------------- | -------------------------------------------------------------------- |
| `has_key(map, "key")`              | Whether the map has the key                                          |
| `has_value(collection, value)`     | Whether the value occurs in the array, or in any of the map's values |
| `except(map, "key", …)`            | The map without those keys                                           |
| `except_matching(map, "regex", …)` | The map without the keys matching any pattern                        |

```text
# Inspect query values except those named "trusted".
any(detect_sqli(except(http.request.uri.args, "trusted")[*][*]))
```

Because `except` returns a map of arrays, the example uses `[*][*]` to reach each value. The `.names` and `.values` fields belong to the original request data and are not properties of the returned map.

## JSON

| Function                         | Returns                                                                                                                      |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `lookup_json_string(s, key, …)`  | The value at the key path as a string; invalid JSON or a missing path gives `""`                                             |
| `lookup_json_integer(s, key, …)` | The integer at the key path; only plain integers count (`42.0` and `"42"` do not), and anything else leaves the value absent |

Keys are string literals for objects and integer literals for array indexes:

```text
lookup_json_string(http.request.body.raw, "users", 0, "name") == "alice"
lookup_json_integer(http.request.body.raw, "quantity") > 1000
```

## JWT

| Function               | Returns                                                               |
| ---------------------- | --------------------------------------------------------------------- |
| `is_jwt_valid("id")`   | Whether the request carries a valid token for the token configuration |
| `is_jwt_present("id")` | Whether any token source has a value                                  |

See [JWT validation](../../protections/jwt-validation/).
