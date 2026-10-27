---
title: Fields
description: "Every field available in expressions, with its type and the phase from which it exists."
sidebar:
  order: 2
---

A field is absent until the phase that provides it, and absent when its source is unavailable: GeoIP without databases, JWT claims without a valid token, schema fields on a host no schema covers. A comparison on an absent field is false.

## Client

Available from `request_headers`.

| Field | Type | Value |
| --- | --- | --- |
| `ip.src` | IP | Client address |
| `ip.src.asnum` | Integer | Autonomous system number (GeoIP) |
| `ip.src.country`, `ip.src.continent` | String | ISO codes (GeoIP) |
| `ip.src.is_in_european_union` | Boolean | (GeoIP) |
| `ip.src.region`, `ip.src.region_code`, `ip.src.city`, `ip.src.postal_code`, `ip.src.metro_code` | String | (GeoIP) |
| `ip.src.lat`, `ip.src.lon` | String | Coordinates (GeoIP) |
| `ip.src.timezone.name` | String | IANA name (GeoIP) |
| `ssl` | Boolean | The client connection uses TLS |

## Request

Available from `request_headers`.

| Field | Type | Value |
| --- | --- | --- |
| `http.request.method` | String | `GET`, `POST`, … |
| `http.request.version` | String | `HTTP/1.1`, `HTTP/2` |
| `http.host` | String | The `Host` header |
| `http.request.full_uri` | String | Scheme, host, path and query |
| `http.request.uri` | String | Path and query |
| `http.request.uri.path` | String | Path |
| `http.request.uri.path.extension` | String | Extension of the last segment |
| `http.request.uri.query` | String | Raw query string |
| `http.request.uri.args` | Map<Array<String>> | Query arguments by name |
| `http.request.uri.args.names`, `.values` | Array<String> | |
| `http.request.headers` | Map<Array<String>> | Headers by lowercase name |
| `http.request.headers.names`, `.values` | Array<String> | |
| `http.request.cookies` | Map<Array<String>> | Cookies by name |
| `http.request.cookies.names`, `.values` | Array<String> | |
| `http.user_agent`, `http.referer`, `http.cookie`, `http.x_forwarded_for` | String | Those headers |
| `http.request.accepted_languages` | Array<String> | From `Accept-Language`, in order |
| `http.request.timestamp.sec`, `.msec` | Integer | When the request arrived |

## Request body

Available from `request_body`.

| Field | Type | Value |
| --- | --- | --- |
| `http.request.body.raw` | String | The body, up to the buffer limit |
| `http.request.body.size` | Integer | Full size in bytes |
| `http.request.body.truncated` | Boolean | The body was larger than the buffer |
| `http.request.body.mime` | String | The `Content-Type` |
| `http.request.body.form` | Map<Array<String>> | Form fields by name (`application/x-www-form-urlencoded`) |
| `http.request.body.form.names`, `.values` | Array<String> | |
| `http.request.body.multipart` | Map<Array<String>> | Multipart parts by name |
| `http.request.body.multipart.names`, `.values`, `.filenames`, `.content_types`, `.content_dispositions`, `.content_transfer_encodings` | Array<…> | Per part |

## Response

Available from `response_headers`; the body from `response_body`.

| Field | Type | Value |
| --- | --- | --- |
| `http.response.code` | Integer | Status |
| `http.response.content_type.media_type` | String | Media type without parameters |
| `http.response.headers` | Map<Array<String>> | Headers by lowercase name |
| `http.response.headers.names`, `.values` | Array<String> | |
| `http.response.body.raw` | String | The body, up to the buffer limit |
| `http.response.body.size` | Integer | Full size |
| `http.response.body.truncated` | Boolean | Larger than the buffer |

## Detections

| Field | Type | From |
| --- | --- | --- |
| `score.{name}` | Integer | A declared [score](../../rules/scores/); refreshed each phase |
| `http.request.jwt.claims.{iss,sub,aud,jti}` | Map<Array<String>> | [JWT validation](../../protections/jwt-validation/#claims), keyed by configuration |
| `http.request.jwt.claims.{iat,nbf}.sec` | Map<Array<Integer>> | |
| `schema_validation.*` | Various | [Schema validation](../../protections/schema-validation/#fields) |
