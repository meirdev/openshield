use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use log::{debug, warn};
use sha1::Sha1;

use crate::config::ChallengeConfig;

type HmacSha1 = Hmac<Sha1>;

pub struct ChallengeManager {
    config: ChallengeConfig,
    challenge_page: String,
}

impl ChallengeManager {
    pub fn new(config: &ChallengeConfig) -> Self {
        let challenge_page = if let Some(ref path) = config.custom_page {
            let html = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("Failed to read challenge page {:?}: {}", path, e));
            html.replace("{{turnstile_site_key}}", &config.turnstile_site_key)
                .replace("{{challenge_path}}", &config.challenge_path)
        } else {
            default_challenge_page(&config.turnstile_site_key, &config.challenge_path)
        };

        Self {
            config: config.clone(),
            challenge_page,
        }
    }

    /// Check if the request has a valid challenge cookie.
    pub fn is_verified(&self, cookie_header: Option<&str>, client_ip: &str) -> bool {
        let Some(cookie_header) = cookie_header else {
            return false;
        };
        let Some(token) = extract_cookie(cookie_header, &self.config.cookie_name) else {
            return false;
        };
        self.verify_cookie(token, client_ip)
    }

    /// Return the challenge HTML page.
    pub fn challenge_page(&self) -> &str {
        &self.challenge_page
    }

    /// Return the challenge POST path.
    pub fn challenge_path(&self) -> &str {
        &self.config.challenge_path
    }

    /// Verify a Turnstile token with Cloudflare's API.
    pub async fn verify_turnstile(&self, token: &str, client_ip: &str) -> bool {
        let client = reqwest::Client::new();
        let resp = client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&[
                ("secret", self.config.turnstile_secret_key.as_str()),
                ("response", token),
                ("remoteip", client_ip),
            ])
            .send()
            .await;

        match resp {
            Ok(r) => {
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    let success = body
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !success {
                        debug!("Turnstile verification failed: {:?}", body);
                    }
                    success
                } else {
                    warn!("Failed to parse Turnstile response");
                    false
                }
            }
            Err(e) => {
                warn!("Turnstile API request failed: {}", e);
                false
            }
        }
    }

    /// Create a signed challenge cookie value.
    pub fn create_cookie(&self, client_ip: &str) -> String {
        let ts = now_secs();
        let payload = format!("{client_ip}|{ts}");
        let sig = hmac_sign(&self.config.cookie_secret, payload.as_bytes());
        let value = format!("{payload}|{sig}");
        let encoded = base64_url_encode(value.as_bytes());
        let name = &self.config.cookie_name;
        format!(
            "{name}={encoded}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            self.config.cookie_ttl
        )
    }

    fn verify_cookie(&self, encoded: &str, client_ip: &str) -> bool {
        let Ok(decoded) = base64_url_decode(encoded) else {
            return false;
        };
        let Ok(value) = std::str::from_utf8(&decoded) else {
            return false;
        };

        let parts: Vec<&str> = value.splitn(3, '|').collect();
        if parts.len() != 3 {
            return false;
        }
        let (ip, ts_str, sig) = (parts[0], parts[1], parts[2]);

        if ip != client_ip {
            return false;
        }

        let Ok(ts) = ts_str.parse::<u64>() else {
            return false;
        };
        if now_secs().saturating_sub(ts) > self.config.cookie_ttl {
            return false;
        }

        let payload = format!("{ip}|{ts_str}");
        let expected_sig = hmac_sign(&self.config.cookie_secret, payload.as_bytes());
        constant_time_eq(sig.as_bytes(), expected_sig.as_bytes())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hmac_sign(key: &str, data: &[u8]) -> String {
    let mut mac = HmacSha1::new_from_slice(key.as_bytes()).unwrap();
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)
}

fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

fn default_challenge_page(site_key: &str, challenge_path: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; }}
        p {{ color: #666; margin-bottom: 1.5rem; }}
        .cf-turnstile {{ display: inline-block; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Check</h1>
        <p>Please verify you are human to continue.</p>
        <form method="POST" action="{challenge_path}">
            <div class="cf-turnstile" data-sitekey="{site_key}" data-callback="onSuccess"></div>
            <input type="hidden" name="redirect" id="redirect">
        </form>
    </div>
    <script>
        document.getElementById('redirect').value = window.location.href;
        function onSuccess(token) {{
            document.querySelector('form').submit();
        }}
    </script>
</body>
</html>"#
    )
}
