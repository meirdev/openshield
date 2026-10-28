---
title: GeoIP
description: "Country, city, ASN and more for the client address, from MaxMind databases."
sidebar:
  order: 5
---

Configure both MaxMind databases to populate the available `ip.src.*` fields for each client address:

```yaml
geoip:
  city_mmdb: ./GeoLite2-City.mmdb
  asn_mmdb: ./GeoLite2-ASN.mmdb
```

| Field                                                    | Example                  |
| -------------------------------------------------------- | ------------------------ |
| `ip.src.country`                                         | `"DE"`                   |
| `ip.src.continent`                                       | `"EU"`                   |
| `ip.src.is_in_european_union`                            | `true`                   |
| `ip.src.region`, `ip.src.region_code`                    | `"Bavaria"`, `"BY"`      |
| `ip.src.city`, `ip.src.postal_code`, `ip.src.metro_code` | `"Munich"`, `"80331"`, … |
| `ip.src.lat`, `ip.src.lon`                               | `"48.1374"`, `"11.5755"` |
| `ip.src.timezone.name`                                   | `"Europe/Berlin"`        |
| `ip.src.asnum`                                           | `3320`                   |

```text
ip.src.country in {"CN" "RU"} and http.request.uri.path contains "/admin"
ip.src.asnum in {16509 14618} and not is_jwt_valid("api")
```

When a database cannot resolve an address, as is common for private and loopback addresses, its fields remain absent. Equality checks on those fields return false, while `!=` can return true, so account for missing results in your rules. Updated databases take effect at startup or after a [reload](../../operations/running/#reload).

The standalone proxy looks up its immediate TCP peer, not an incoming `X-Forwarded-For` value. See [Client addresses](../../configuration/proxy/#client-addresses-and-forwarded-headers) when deploying behind another proxy.
