use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use log::debug;
use serde_json::{Map, Value};
use wirefilter_engine::{ExecutionContext, FilterValue, GetType, LhsValue, Scheme, Type};

use super::functions::RuleCompiler;
use crate::config;

pub type Claims = Map<String, Value>;

/// Clock skew tolerated when checking `exp` and `nbf`, in seconds.
const LEEWAY: u64 = 60;

const MIN_RSA_BITS: usize = 2048;

struct Key {
    kid: String,
    alg: Algorithm,
    key: DecodingKey,
    validation: Validation,
}

struct TokenConfig {
    id: String,
    sources: Vec<FilterValue>,
    keys: Vec<Key>,
}

/// What one token configuration found on a request.
pub struct TokenOutcome<'a> {
    pub id: &'a str,
    /// Some token source had a value.
    pub present: bool,
    /// Claims of the first token that verified, if any.
    pub claims: Option<Claims>,
}

pub struct JwtValidator {
    configs: Vec<TokenConfig>,
}

impl JwtValidator {
    pub fn new(
        configs: &[config::TokenConfig],
        scheme: &Scheme,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let configs = configs
            .iter()
            .map(|cfg| {
                TokenConfig::new(cfg, scheme)
                    .map_err(|e| format!("token configuration '{}': {}", cfg.id, e))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { configs })
    }

    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    /// Look for a token for each configuration in the request fields already
    /// set on `ctx`, and verify it.
    pub fn evaluate<'s>(&'s self, ctx: &ExecutionContext<'_>) -> Vec<TokenOutcome<'s>> {
        self.configs.iter().map(|cfg| cfg.evaluate(ctx)).collect()
    }
}

impl TokenConfig {
    fn new(cfg: &config::TokenConfig, scheme: &Scheme) -> Result<Self, String> {
        let sources = cfg
            .token_sources
            .iter()
            .map(|expr| {
                compile_source(expr, scheme).map_err(|e| format!("token source '{expr}': {e}"))
            })
            .collect::<Result<_, _>>()?;
        let keys = cfg
            .credentials
            .keys
            .iter()
            .enumerate()
            .map(|(i, jwk)| {
                Key::new(jwk).map_err(|e| match &jwk.common.key_id {
                    Some(kid) => format!("key '{kid}': {e}"),
                    None => format!("key #{}: {e}", i + 1),
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            id: cfg.id.clone(),
            sources,
            keys,
        })
    }

    fn evaluate(&self, ctx: &ExecutionContext<'_>) -> TokenOutcome<'_> {
        let mut present = false;
        let mut claims = None;
        for source in &self.sources {
            let Ok(Ok(LhsValue::Bytes(value))) = source.execute(ctx) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            present = true;
            let token = value.strip_prefix(b"Bearer ").unwrap_or(&value);
            match self.verify(token) {
                Ok(verified) => {
                    claims = Some(verified);
                    break;
                }
                Err(reason) => debug!("token configuration '{}': {}", self.id, reason),
            }
        }
        TokenOutcome {
            id: &self.id,
            present,
            claims,
        }
    }

    fn verify(&self, token: &[u8]) -> Result<Claims, String> {
        let header = decode_header(token).map_err(|e| e.to_string())?;
        let kid = header.kid.ok_or("token has no 'kid'")?;
        // Selecting on `alg` as well as `kid` means the token cannot choose
        // how a key is used.
        let key = self
            .keys
            .iter()
            .find(|k| k.kid == kid && k.alg == header.alg)
            .ok_or_else(|| format!("no key with kid '{kid}' and alg {:?}", header.alg))?;
        decode::<Claims>(token, &key.key, &key.validation)
            .map(|data| data.claims)
            .map_err(|e| e.to_string())
    }
}

impl Key {
    fn new(jwk: &Jwk) -> Result<Self, String> {
        let kid = jwk.common.key_id.clone().ok_or("missing 'kid'")?;
        let key_alg = jwk.common.key_algorithm.ok_or("missing 'alg'")?;
        let alg: Algorithm = key_alg
            .to_string()
            .parse()
            .map_err(|_| format!("unsupported 'alg' {key_alg}"))?;

        use Algorithm::*;
        match (&jwk.algorithm, alg) {
            (AlgorithmParameters::RSA(rsa), RS256 | RS384 | RS512 | PS256 | PS384 | PS512) => {
                let modulus = decode_base64url(&rsa.n, "n")?;
                let bits = modulus.iter().skip_while(|&&b| b == 0).count() * 8;
                if bits < MIN_RSA_BITS {
                    return Err(format!(
                        "RSA key is {bits} bits; at least {MIN_RSA_BITS} required"
                    ));
                }
            }
            (AlgorithmParameters::EllipticCurve(ec), ES256 | ES384) => {
                let expected = if alg == ES256 {
                    EllipticCurve::P256
                } else {
                    EllipticCurve::P384
                };
                if ec.curve != expected {
                    return Err(format!("'alg' {alg:?} requires curve {expected:?}"));
                }
            }
            (AlgorithmParameters::OctetKey(oct), HS256 | HS384 | HS512) => {
                let min = match alg {
                    HS256 => 32,
                    HS384 => 48,
                    _ => 64,
                };
                let len = decode_base64url(&oct.value, "k")?.len();
                if len < min {
                    return Err(format!(
                        "secret is {len} bytes; {alg:?} requires at least {min}"
                    ));
                }
            }
            _ => return Err(format!("'alg' {alg:?} is not supported for this key type")),
        }

        let key = DecodingKey::from_jwk(jwk).map_err(|e| e.to_string())?;

        // `exp` and `nbf` are checked when present but neither is required,
        // and `aud` is left to rule expressions.
        let mut validation = Validation::new(alg);
        validation.required_spec_claims.clear();
        validation.validate_nbf = true;
        validation.validate_aud = false;
        validation.leeway = LEEWAY;

        Ok(Self {
            kid,
            alg,
            key,
            validation,
        })
    }
}

fn decode_base64url(value: &str, name: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("'{name}' is not unpadded base64url"))
}

fn compile_source(expr: &str, scheme: &Scheme) -> Result<FilterValue, String> {
    let ast = scheme.parse_value(expr).map_err(|e| e.to_string())?;
    if ast.get_type() != Type::Bytes {
        return Err("must evaluate to a string".into());
    }
    Ok(ast.compile_with_compiler(&mut RuleCompiler::new(scheme)))
}

#[cfg(test)]
pub(crate) mod test_support {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
    use serde_json::Value;

    pub const HS_KID: &str = "hs-1";
    pub const HS_SECRET: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    /// YAML for a token configuration `id` that reads the `Authorization`
    /// header, then the `jwt` cookie, and trusts [`HS_SECRET`].
    pub fn hs256_config(id: &str) -> String {
        use base64::Engine as _;
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(HS_SECRET);
        format!(
            r#"
  - id: {id}
    token_sources:
      - 'http.request.headers["authorization"][0]'
      - 'http.request.cookies["jwt"][0]'
    credentials:
      keys:
        - {{kty: oct, kid: {HS_KID}, alg: HS256, k: {k}}}
"#
        )
    }

    pub fn now() -> u64 {
        get_current_timestamp()
    }

    pub fn sign(alg: Algorithm, kid: Option<&str>, key: &EncodingKey, claims: &Value) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(String::from);
        encode(&header, claims, key).expect("token should encode")
    }

    /// A token signed with [`HS_SECRET`] under [`HS_KID`].
    pub fn hs256_token(claims: &Value) -> String {
        sign(
            Algorithm::HS256,
            Some(HS_KID),
            &EncodingKey::from_secret(HS_SECRET),
            claims,
        )
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use super::test_support::*;
    use super::*;
    use crate::waf::data::RequestData;
    use crate::waf::populate::request_fields;
    use crate::waf::populate::test_support::empty_request;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn token_configs(yaml: &str) -> Vec<config::TokenConfig> {
        serde_yaml::from_str(yaml).expect("token configurations should parse")
    }

    fn build(yaml: &str) -> Result<(Scheme, JwtValidator), String> {
        let configs = token_configs(yaml);
        let ids: Vec<String> = configs.iter().map(|c| c.id.clone()).collect();
        let scheme = crate::waf::scheme::build(&[], &ids);
        let validator = JwtValidator::new(&configs, &scheme).map_err(|e| e.to_string())?;
        Ok((scheme, validator))
    }

    fn build_err(yaml: &str) -> String {
        match build(yaml) {
            Ok(_) => panic!("expected the token configuration to be rejected"),
            Err(e) => e,
        }
    }

    /// YAML for one configuration `api` reading the `Authorization` header
    /// with a single key.
    fn with_key(key: &str) -> String {
        format!(
            "- id: api\n  token_sources: ['http.request.headers[\"authorization\"][0]']\n  \
             credentials:\n    keys:\n      - {key}\n"
        )
    }

    /// Outcome of the single configuration in `yaml` for a request carrying
    /// `headers`.
    fn outcome(yaml: &str, headers: &[(&str, &str)]) -> (bool, Option<Claims>) {
        let (scheme, validator) = build(yaml).expect("token configuration should build");
        let mut req: RequestData = empty_request();
        req.headers = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut ctx = crate::waf::scheme::new_context(&scheme);
        request_fields(&mut ctx, &scheme, &req);
        let mut outcomes = validator.evaluate(&ctx);
        assert_eq!(outcomes.len(), 1);
        let o = outcomes.remove(0);
        (o.present, o.claims)
    }

    fn hs256(headers: &[(&str, &str)]) -> (bool, Option<Claims>) {
        outcome(hs256_config("api").trim_start_matches('\n'), headers)
    }

    fn is_valid(token: &str) -> bool {
        hs256(&[("authorization", token)]).1.is_some()
    }

    #[test]
    fn valid_token_yields_claims() {
        let token = hs256_token(&json!({"sub": "alice", "exp": now() + 300}));
        let (present, claims) = hs256(&[("authorization", &token)]);
        assert!(present);
        assert_eq!(claims.unwrap()["sub"], "alice");
    }

    #[test]
    fn bearer_prefix_is_optional_and_exact() {
        let token = hs256_token(&json!({"sub": "alice"}));
        assert!(is_valid(&format!("Bearer {token}")));
        assert!(is_valid(&token));
        // Only the exact prefix is stripped.
        assert!(!is_valid(&format!("bearer {token}")));
        assert!(!is_valid(&format!("Bearer  {token}")));
        assert!(!is_valid(&format!("Bearer: {token}")));
    }

    #[test]
    fn missing_token_is_neither_present_nor_valid() {
        let (present, claims) = hs256(&[]);
        assert!(!present);
        assert!(claims.is_none());

        let (present, _) = hs256(&[("authorization", "")]);
        assert!(!present, "an empty value is not a token");
    }

    #[test]
    fn garbage_is_present_but_invalid() {
        for value in ["Basic dXNlcjpwYXNz", "Bearer not.a.jwt", "a.b"] {
            let (present, claims) = hs256(&[("authorization", value)]);
            assert!(present, "{value}");
            assert!(claims.is_none(), "{value}");
        }
    }

    #[test]
    fn tampered_or_wrongly_signed_token_is_invalid() {
        let token = hs256_token(&json!({"sub": "alice"}));

        // Swap the payload while keeping the original signature.
        let parts: Vec<&str> = token.split('.').collect();
        let forged_payload = b64(br#"{"sub":"admin"}"#);
        assert!(!is_valid(&format!(
            "{}.{}.{}",
            parts[0], forged_payload, parts[2]
        )));

        let other = sign(
            Algorithm::HS256,
            Some(HS_KID),
            &EncodingKey::from_secret(b"another-secret-another-secret-00"),
            &json!({"sub": "alice"}),
        );
        assert!(!is_valid(&other));
    }

    #[test]
    fn unsigned_token_is_invalid() {
        let header = b64(format!(r#"{{"alg":"none","kid":"{HS_KID}"}}"#).as_bytes());
        let payload = b64(br#"{"sub":"admin"}"#);
        assert!(!is_valid(&format!("{header}.{payload}.")));
    }

    #[test]
    fn exp_and_nbf_are_checked_with_leeway() {
        let valid = |claims: Value| is_valid(&hs256_token(&claims));

        assert!(valid(json!({})), "exp and nbf are optional");
        assert!(valid(json!({"exp": now() + 300, "nbf": now() - 300})));

        assert!(valid(json!({"exp": now() - 30})), "within leeway");
        assert!(!valid(json!({"exp": now() - 120})), "expired");

        assert!(valid(json!({"nbf": now() + 30})), "within leeway");
        assert!(!valid(json!({"nbf": now() + 120})), "not yet valid");

        assert!(!valid(json!({"exp": "tomorrow"})), "malformed exp");
        assert!(!valid(json!({"nbf": "yesterday"})), "malformed nbf");
    }

    #[test]
    fn audience_is_not_validated() {
        assert!(is_valid(&hs256_token(&json!({"aud": ["a", "b"]}))));
    }

    #[test]
    fn kid_must_be_present_and_known() {
        let key = EncodingKey::from_secret(HS_SECRET);
        let claims = json!({"sub": "alice"});
        assert!(!is_valid(&sign(Algorithm::HS256, None, &key, &claims)));
        assert!(!is_valid(&sign(
            Algorithm::HS256,
            Some("other"),
            &key,
            &claims
        )));
    }

    #[test]
    fn token_alg_must_match_the_key_alg() {
        // The secret is long enough for HS384, but the key is HS256-only.
        let token = sign(
            Algorithm::HS384,
            Some(HS_KID),
            &EncodingKey::from_secret(HS_SECRET),
            &json!({"sub": "alice"}),
        );
        assert!(!is_valid(&token));
    }

    #[test]
    fn sources_are_tried_until_one_is_valid() {
        let token = hs256_token(&json!({"sub": "from-cookie"}));
        let cookie = format!("jwt={token}");

        let (present, claims) = hs256(&[("cookie", &cookie)]);
        assert!(present);
        assert_eq!(claims.unwrap()["sub"], "from-cookie");

        // An invalid token in an earlier source does not hide a valid one.
        let (present, claims) = hs256(&[("authorization", "Bearer junk"), ("cookie", &cookie)]);
        assert!(present);
        assert_eq!(claims.unwrap()["sub"], "from-cookie");

        // The first valid token wins.
        let first = hs256_token(&json!({"sub": "from-header"}));
        let (_, claims) = hs256(&[("authorization", &first), ("cookie", &cookie)]);
        assert_eq!(claims.unwrap()["sub"], "from-header");
    }

    /// A generated P-256 key pair as (JWK YAML, signing key).
    fn es256_key(kid: &str) -> (String, EncodingKey) {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        // Uncompressed point: 0x04 || x || y.
        let point = pair.public_key().as_ref();
        let jwk = format!(
            "{{kty: EC, crv: P-256, kid: {kid}, alg: ES256, x: {}, y: {}}}",
            b64(&point[1..33]),
            b64(&point[33..65]),
        );
        let pkcs8 = pair.to_pkcs8v1().unwrap();
        (jwk, EncodingKey::from_ec_der(pkcs8.as_ref()))
    }

    #[test]
    fn es256_token_verifies_against_its_public_jwk() {
        let (jwk, signing_key) = es256_key("ec-1");
        let (_, other_signing_key) = es256_key("ec-1");
        let yaml = with_key(&jwk);
        let claims = json!({"iss": "https://issuer.example"});

        let token = sign(Algorithm::ES256, Some("ec-1"), &signing_key, &claims);
        let (present, verified) = outcome(&yaml, &[("authorization", &token)]);
        assert!(present);
        assert_eq!(verified.unwrap()["iss"], "https://issuer.example");

        let forged = sign(Algorithm::ES256, Some("ec-1"), &other_signing_key, &claims);
        assert!(outcome(&yaml, &[("authorization", &forged)]).1.is_none());
    }

    #[test]
    fn public_key_cannot_be_used_as_hmac_secret() {
        // Algorithm confusion: sign with HS256 using the EC public key bytes.
        let (jwk, _) = es256_key("ec-1");
        let configs = token_configs(&with_key(&jwk));
        let AlgorithmParameters::EllipticCurve(ec) = &configs[0].credentials.keys[0].algorithm
        else {
            panic!("expected an EC key");
        };
        let token = sign(
            Algorithm::HS256,
            Some("ec-1"),
            &EncodingKey::from_secret(ec.x.as_bytes()),
            &json!({"sub": "admin"}),
        );
        assert!(
            outcome(&with_key(&jwk), &[("authorization", &token)])
                .1
                .is_none()
        );
    }

    #[test]
    fn keys_require_kid_and_alg() {
        let k = b64(HS_SECRET);
        let err = build_err(&with_key(&format!("{{kty: oct, alg: HS256, k: {k}}}")));
        assert!(
            err.contains("token configuration 'api': key #1: missing 'kid'"),
            "{err}"
        );

        let err = build_err(&with_key(&format!("{{kty: oct, kid: a, k: {k}}}")));
        assert!(err.contains("key 'a': missing 'alg'"), "{err}");
    }

    #[test]
    fn weak_or_mismatched_keys_are_rejected() {
        let short = b64(&[0u8; 31]);
        let err = build_err(&with_key(&format!(
            "{{kty: oct, kid: a, alg: HS256, k: {short}}}"
        )));
        assert!(err.contains("secret is 31 bytes"), "{err}");

        // 32 bytes is enough for HS256 but not HS512.
        let k = b64(HS_SECRET);
        let err = build_err(&with_key(&format!(
            "{{kty: oct, kid: a, alg: HS512, k: {k}}}"
        )));
        assert!(err.contains("requires at least 64"), "{err}");

        let err = build_err(&with_key(&format!(
            "{{kty: oct, kid: a, alg: RS256, k: {k}}}"
        )));
        assert!(err.contains("not supported for this key type"), "{err}");

        let (x, y) = (b64(&[1u8; 32]), b64(&[2u8; 32]));
        let err = build_err(&with_key(&format!(
            "{{kty: EC, crv: P-256, kid: a, alg: ES384, x: {x}, y: {y}}}"
        )));
        assert!(err.contains("requires curve P384"), "{err}");

        let n = b64(&[0xff; 128]);
        let err = build_err(&with_key(&format!(
            "{{kty: RSA, kid: a, alg: RS256, n: {n}, e: AQAB}}"
        )));
        assert!(err.contains("RSA key is 1024 bits"), "{err}");

        let err = build_err(&with_key(&format!(
            "{{kty: OKP, crv: Ed25519, kid: a, alg: EdDSA, x: {x}}}"
        )));
        assert!(err.contains("not supported for this key type"), "{err}");
    }

    #[test]
    fn rsa_key_of_sufficient_size_is_accepted() {
        let n = b64(&[0xff; 256]);
        for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
            build(&with_key(&format!(
                "{{kty: RSA, kid: a, alg: {alg}, n: {n}, e: AQAB}}"
            )))
            .unwrap_or_else(|e| panic!("{alg}: {e}"));
        }
    }

    #[test]
    fn token_source_must_be_a_string_expression() {
        let k = b64(HS_SECRET);
        let config = |source: &str| {
            format!(
                "- id: api\n  token_sources: ['{source}']\n  credentials:\n    keys:\n      - \
                 {{kty: oct, kid: a, alg: HS256, k: {k}}}\n"
            )
        };

        let err = build_err(&config("http.request.headers"));
        assert!(err.contains("must evaluate to a string"), "{err}");

        let err = build_err(&config("http.nope"));
        assert!(
            err.contains("token configuration 'api': token source 'http.nope'"),
            "{err}"
        );

        build(&config("lower(http.request.uri.args[\"token\"][0])")).unwrap();
    }
}
