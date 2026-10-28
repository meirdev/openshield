---
title: Lists
description: "Named sets of IP ranges or strings, referenced from expressions with $name."
sidebar:
  order: 5
---

Define lists at the top level and reference them with `$name`:

```yaml
lists:
  - name: office
    kind: ip
    items: ["203.0.113.0/24", "2001:db8::/32", "198.51.100.7"]
  - name: blocked_ua
    kind: string
    items: ["sqlmap", "nikto"]
  - name: scanner_ua
    kind: substring
    items: ["sqlmap", "nikto", "nmap"]
```

```text
ip.src in $office
http.user_agent in $blocked_ua
http.user_agent in $scanner_ua
```

| `kind`      | Matches when                                                    |
| ----------- | --------------------------------------------------------------- |
| `ip`        | The address equals an item or lies inside one of the CIDRs      |
| `string`    | The whole value equals an item, case-sensitively                |
| `substring` | Any item occurs anywhere in the value, ASCII case-insensitively |

Names are unique and `kind` is required; a misspelled kind is a configuration error. Lists are compiled at startup and shared across requests. Substring lists use an Aho-Corasick matcher rather than checking each item separately, but matching still has a cost, and larger lists require more memory and startup work.

For example, `sqlmap/1.7` matches `scanner_ua` but not `blocked_ua`: the first list looks for substrings, while the second requires the entire value to equal an item. To change a list, update the configuration and reload the host.
