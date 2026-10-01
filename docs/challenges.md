# Turnstile challenges

Use `action: challenge` to require browser verification before forwarding a request. OpenShield serves a Turnstile page and verifies the result with Cloudflare.

## Setup

Add your Turnstile keys and a secret for signing verification cookies:

```yaml
challenge:
  turnstile_site_key: "your-site-key"
  turnstile_secret_key: "your-secret-key"
  cookie_secret: "your-random-cookie-signing-secret"

rules:
  - id: challenge-admin
    phase: request_headers
    action: challenge
    expression: 'starts_with(http.request.uri.path, "/admin/")'
```

| Setting                | Default                   | Purpose                                      |
| ---------------------- | ------------------------- | -------------------------------------------- |
| `turnstile_site_key`   | Required                  | Public key used by the widget                |
| `turnstile_secret_key` | Required                  | Secret used to verify tokens with Cloudflare |
| `cookie_secret`        | Required                  | Secret used to sign verification cookies     |
| `cookie_ttl`           | `3600`                    | Cookie lifetime in seconds                   |
| `cookie_name`          | `oss_challenge`           | Verification cookie name                     |
| `challenge_path`       | `/__openshield/challenge` | Endpoint that receives verification tokens   |
| `custom_page`          | Omitted                   | Path to a custom HTML page                   |

## Verification flow

1. A challenge rule matches. A valid verification cookie lets the request continue to the upstream.
2. Without a valid cookie, OpenShield returns the challenge page with status `403`.
3. The browser submits the Turnstile token to `challenge_path`.
4. OpenShield verifies the token with Cloudflare. On success, it sets a signed cookie bound to the client IP and redirects to the original URL. On failure, it returns the challenge page again.

## Custom page

Set `challenge.custom_page` to an HTML file. OpenShield replaces two placeholders when loading it:

| Placeholder              | Replaced with             |
| ------------------------ | ------------------------- |
| `{{turnstile_site_key}}` | The configured site key   |
| `{{challenge_path}}`     | The verification endpoint |

Include a Turnstile widget and a form that posts to `{{challenge_path}}`. Submit the widget’s `cf-turnstile-response` field and a hidden `redirect` field containing the original URL. Set `redirect` in browser JavaScript, as the default page does.
