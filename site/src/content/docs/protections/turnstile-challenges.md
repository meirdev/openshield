---
title: Turnstile challenges
description: "Require browser verification with Cloudflare Turnstile before forwarding a request."
sidebar:
  order: 4
---

`action: challenge` serves a [Turnstile](https://www.cloudflare.com/products/turnstile/) page. Successful verification sets an IP-bound signed cookie and redirects the browser back. Replace the placeholder keys and secret below with your own values:

```yaml
challenge:
  turnstile_site_key: "your-site-key"
  turnstile_secret_key: "your-secret-key"
  cookie_secret: "a-long-random-secret"

rulesets:
  - name: main
    kind: root
    rules:
      - id: challenge-admin
        action: challenge
        expression: 'starts_with(http.request.uri.path, "/admin/")'
```

| Setting                | Default                   | Purpose                                     |
| ---------------------- | ------------------------- | ------------------------------------------- |
| `turnstile_site_key`   | Required                  | Public key the widget uses                  |
| `turnstile_secret_key` | Required                  | Secret for verifying tokens with Cloudflare |
| `cookie_secret`        | Required                  | Signs the verification cookie               |
| `cookie_ttl`           | `3600`                    | Cookie lifetime in seconds                  |
| `cookie_name`          | `oss_challenge`           | Cookie name                                 |
| `challenge_path`       | `/__openshield/challenge` | Where the page posts the Turnstile token    |
| `custom_page`          | Omitted                   | Your own HTML page                          |

Challenges are enforced only in `request_headers`. In later phases, a matching challenge still ends that phase's rule evaluation, but no challenge page is served.

A challenge match ends header-rule evaluation even when the client has a valid cookie, so place mandatory blocking checks before it. Later phases still run, but the verification redirect does not replay an original POST body; use challenges on browser navigation paths rather than API submissions.

## Flow

1. A challenge rule matches. With a valid cookie bound to the client IP, the request continues.
2. Without one, OpenShield answers `403` with the challenge page.
3. The page submits the Turnstile token to `challenge_path`.
4. OpenShield asks Cloudflare. On success it sets the cookie and redirects to the original URL; on failure it serves the page again.

In the proxy, the call to Cloudflare has a five-second timeout and a failure counts as not verified. The [nginx module](../../hosts/nginx-module/#challenges) makes the same call through an internal location.

## Custom page

`custom_page` names an HTML file in which two placeholders are replaced when it is loaded:

| Placeholder              | Replaced with             |
| ------------------------ | ------------------------- |
| `{{turnstile_site_key}}` | The site key              |
| `{{challenge_path}}`     | The verification endpoint |

Include the Turnstile widget and a form posting to `{{challenge_path}}` with the widget's `cf-turnstile-response` field and a hidden `redirect` field holding the original URL, set from JavaScript as the default page does.
