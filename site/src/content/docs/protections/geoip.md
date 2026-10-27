---
title: GeoIP
description: "Country, city, ASN and more for the client address, from MaxMind databases."
sidebar:
  order: 5
---

With the two MaxMind databases configured, every request gets the `ip.src.*` fields:

```yaml
geoip:
  city_mmdb: ./GeoLite2-City.mmdb
  asn_mmdb: ./GeoLite2-ASN.mmdb
```

| Field | Example |
| --- | --- |
| `ip.src.country` | `"DE"` |
| `ip.src.continent` | `"EU"` |
| `ip.src.is_in_european_union` | `true` |
| `ip.src.region`, `ip.src.region_code` | `"Bavaria"`, `"BY"` |
| `ip.src.city`, `ip.src.postal_code`, `ip.src.metro_code` | `"Munich"`, `"80331"`, … |
| `ip.src.lat`, `ip.src.lon` | `"48.1374"`, `"11.5755"` |
| `ip.src.timezone.name` | `"Europe/Berlin"` |
| `ip.src.asnum` | `3320` |

```text
ip.src.country in {"CN" "RU"} and http.request.uri.path contains "/admin"
ip.src.asnum in {16509 14618} and not is_jwt_valid("api")
```

Fields a database cannot resolve are absent, which makes comparisons on them false. GeoLite2 databases are free from MaxMind with an account; the paid GeoIP2 databases have the same layout. Databases are read at startup and after a [reload](../../operations/running/#reload).
