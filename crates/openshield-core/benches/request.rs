//! Per-request cost of the WAF core and the hot spots found in review. Run
//! with `cargo bench -p openshield-core --bench request`.
//!
//! Benchmarks named `*/current` measure the implementation in the crate;
//! their siblings measure a candidate replacement written here.

use std::collections::{HashMap, HashSet};
use std::hint::black_box;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use openshield_core::config::WafConfig;
use openshield_core::waf::data::{RequestData, ResponseData};
use openshield_core::waf::jwt::JwtValidator;
use openshield_core::waf::ratelimit::{Limits, MemoryStore, RateLimitKey, RateLimitStore};
use openshield_core::waf::schema::SchemaValidator;
use openshield_core::waf::{lists, populate, scheme};
use openshield_core::{ResponseOutcome, Waf};
use openshield_openapi::{CompiledSpec, Match};
use wirefilter_engine::{Bytes as WfBytes, TypedArray, TypedMap};

const PETSTORE: &str = r#"
openapi: 3.1.0
info: {title: Pets, version: "1"}
servers: [{url: /api/v1}]
paths:
  /pets:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, maximum: 100}}
      responses: {"200": {description: ok}}
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name: {type: string, minLength: 1}
                age: {type: integer}
                notes: {type: string}
      responses: {"201": {description: created}}
  /pets/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses: {"200": {description: ok}}
"#;

const JWT_SECRET: &[u8] = b"openshield-demo-secret-change-me!";
const JWT_SECRET_B64: &str = "b3BlbnNoaWVsZC1kZW1vLXNlY3JldC1jaGFuZ2UtbWUh";

/// A ruleset of the shape a real deployment has: lists, scored detections,
/// a few path rules, a rate limit. Ends inside the root ruleset's rule list
/// so callers can append rules.
const RULES: &str = r#"
rulesets:
  - name: detections
    rules:
      - id: sqli-args
        action: score
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
        action_parameters: {scores: [{name: sqli, increment: 10}]}
      - id: xss-args
        action: score
        expression: "any(detect_xss(url_decode_uni(http.request.uri.args.values[*])))"
        action_parameters: {scores: [{name: xss, increment: 10}]}
      - id: sqli-cookies
        action: score
        expression: "any(detect_sqli(url_decode_uni(http.request.cookies.values[*])))"
        action_parameters: {scores: [{name: sqli, increment: 5}]}
      - id: sqli-ua
        action: score
        expression: "detect_sqli(http.user_agent)"
        action_parameters: {scores: [{name: sqli, increment: 3}]}
  - name: main
    kind: root
    rules:
      - id: blocked-ips
        action: block
        expression: "ip.src in $blocked_ips"
      - id: scanners
        action: block
        expression: "http.user_agent in $scanner_ua"
      - id: admin-office-only
        action: block
        expression: 'starts_with(http.request.uri.path, "/admin/") and not ip.src in $office'
      - id: no-php
        action: block
        expression: 'lower(http.request.uri.path) matches "\\.(php|asp|jsp)$"'
      - id: login-rate-limit
        action: block
        expression: 'http.request.method == "POST" and http.request.uri.path == "/login"'
        ratelimit: {characteristics: [ip.src], period: 60, requests_per_period: 100}
      - id: run-detections
        action: execute
        expression: "true"
        action_parameters: {id: detections}
      - id: log-5xx
        phase: response_headers
        action: log
        expression: "http.response.code >= 500"
"#;

const BODY_RULE: &str = r#"
      - id: block-injection
        phase: request_body
        action: block
        expression: "score.sqli >= 10 or score.xss >= 10"
"#;

const LOG_EVERY_REQUEST: &str = r#"
      - id: log-all
        action: log
        expression: "true"
"#;

#[derive(Default)]
struct Opts {
    blocked_ips: Option<Vec<String>>,
    body_rule: bool,
    log_every_request: bool,
    inspect_response_body: bool,
    jwt_and_schema: bool,
    text_audit: bool,
}

fn config(opts: &Opts) -> String {
    let default_blocked = ["203.0.113.0/24".to_string(), "198.51.100.0/24".to_string()];
    let blocked = opts.blocked_ips.as_deref().unwrap_or(&default_blocked);
    let mut yaml = format!(
        r#"
audit_log: {{path: /dev/null, format: {}}}
inspect_response_body: {}
scores: [sqli, xss]
lists:
  - name: blocked_ips
    kind: ip
    items: [{}]
  - name: office
    kind: ip
    items: ["10.0.0.0/8"]
  - name: scanner_ua
    kind: substring
    items: [sqlmap, nikto, nmap, masscan, zgrab, nuclei, wpscan, dirbuster]
"#,
        if opts.text_audit { "text" } else { "json" },
        opts.inspect_response_body,
        blocked.join(", ")
    );
    if opts.jwt_and_schema {
        yaml.push_str(&jwt_and_schema());
    }
    yaml.push_str(RULES);
    if opts.body_rule {
        yaml.push_str(BODY_RULE);
    }
    if opts.log_every_request {
        yaml.push_str(LOG_EVERY_REQUEST);
    }
    yaml
}

fn jwt_and_schema() -> String {
    let spec = std::env::temp_dir().join(format!("openshield-bench-{}.yaml", std::process::id()));
    std::fs::write(&spec, PETSTORE).unwrap();
    format!(
        r#"
token_configurations:
  - id: api
    token_sources: ['http.request.headers["authorization"][0]']
    credentials:
      keys:
        - {{kty: oct, kid: k1, alg: HS256, k: {JWT_SECRET_B64}}}
schemas:
  - name: pets
    file: {}
"#,
        spec.display()
    )
}

fn waf(opts: &Opts) -> Arc<Waf> {
    let config = WafConfig::from_yaml(&config(opts)).expect("config");
    Arc::new(Waf::from_config(&config).expect("waf"))
}

/// A browser-like request with the headers, cookies and arguments a typical
/// API call carries.
fn request(ip: &str, method: &str, path: &str, query: &str) -> RequestData {
    let headers = [
        ("host", "api.example.com"),
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
        ),
        ("accept", "application/json, text/plain, */*"),
        ("accept-language", "en-US,en;q=0.9,de;q=0.8"),
        ("accept-encoding", "gzip, deflate, br"),
        (
            "authorization",
            "Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0.e30.x",
        ),
        (
            "cookie",
            "session=4f9c2b7e1a; theme=dark; lang=en; consent=1; ab=variant-b",
        ),
        ("content-type", "application/json"),
        ("x-request-id", "4d1b7c0e-5a2f-4b3c-9d8e-1f2a3b4c5d6e"),
        ("x-forwarded-for", "203.0.113.9, 10.0.0.2"),
        ("referer", "https://app.example.com/dashboard"),
        ("sec-fetch-mode", "cors"),
    ];
    let uri = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    RequestData {
        client_ip: Some(ip.parse::<IpAddr>().unwrap()),
        is_tls: true,
        method: method.into(),
        version: "HTTP/1.1".into(),
        host: "api.example.com".into(),
        full_uri: format!("https://api.example.com{uri}"),
        uri,
        path: path.into(),
        query: query.into(),
        extension: String::new(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        geo: None,
    }
}

fn with_header(mut req: RequestData, name: &str, value: Option<&str>) -> RequestData {
    req.headers.retain(|(k, _)| k != name);
    if let Some(value) = value {
        req.headers.push((name.into(), value.into()));
    }
    req
}

fn benign() -> RequestData {
    request(
        "192.0.2.10",
        "GET",
        "/api/v1/pets/42",
        "limit=10&sort=name&page=2&fields=name,age&include=owner",
    )
}

fn attack() -> RequestData {
    request("192.0.2.10", "GET", "/search", "q=1'%20OR%20'1'='1&page=2")
}

fn blocked_ip() -> RequestData {
    request("203.0.113.5", "GET", "/", "")
}

fn post_json() -> RequestData {
    request("192.0.2.10", "POST", "/api/v1/pets", "")
}

fn response_headers() -> Vec<(String, String)> {
    vec![
        ("content-type".into(), "application/json".into()),
        ("content-length".into(), "128".into()),
        ("cache-control".into(), "no-store".into()),
        (
            "x-request-id".into(),
            "4d1b7c0e-5a2f-4b3c-9d8e-1f2a3b4c5d6e".into(),
        ),
    ]
}

fn json_body(size: usize) -> Vec<u8> {
    let prefix = br#"{"name":"rex","age":3,"notes":""#;
    let suffix = br#""}"#;
    let mut body = prefix.to_vec();
    body.resize(size.saturating_sub(suffix.len()), b'a');
    body.extend_from_slice(suffix);
    body
}

fn multipart_body(parts: usize, part_size: usize) -> (String, Vec<u8>) {
    let boundary = "----openshield-bench";
    let mut body = Vec::new();
    for i in 0..parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"field{i}\"\r\n\r\n").as_bytes(),
        );
        body.resize(body.len() + part_size, b'a');
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

fn valid_token() -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let claims = serde_json::json!({
        "sub": "user-42", "iss": "openshield", "aud": "api", "exp": exp,
        "scope": "pets:read pets:write",
    });
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k1".into());
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET)).unwrap()
}

/// Formats every record like a real logger would, then discards it.
struct SinkLogger;

impl log::Log for SinkLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let _ = writeln!(
            std::io::sink(),
            "[{} {}] {}",
            record.level(),
            record.target(),
            record.args()
        );
    }

    fn flush(&self) {}
}

static LOGGER: SinkLogger = SinkLogger;

fn transaction(c: &mut Criterion) {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Off);

    let base = waf(&Opts {
        body_rule: true,
        ..Opts::default()
    });
    let full = waf(&Opts {
        body_rule: true,
        jwt_and_schema: true,
        ..Opts::default()
    });

    let mut group = c.benchmark_group("transaction");
    group.throughput(Throughput::Elements(1));
    for (name, waf) in [("base", &base), ("jwt+schema", &full)] {
        for (kind, make) in [
            ("benign", benign as fn() -> RequestData),
            ("attack", attack),
        ] {
            group.bench_with_input(
                BenchmarkId::new(format!("request_headers/{kind}"), name),
                waf,
                |b, waf| {
                    b.iter_batched(
                        make,
                        |req| {
                            let mut tx = waf.transaction();
                            black_box(tx.request_headers(req))
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }
        group.bench_with_input(
            BenchmarkId::new("full_cycle/benign", name),
            waf,
            |b, waf| {
                b.iter_batched(
                    benign,
                    |req| {
                        let mut tx = waf.transaction();
                        black_box(tx.request_headers(req));
                        black_box(tx.request_body_chunk(b"", true));
                        black_box(tx.response_headers(ResponseData {
                            status: 200,
                            headers: response_headers(),
                        }));
                        black_box(tx.response_body_chunk(b"{\"ok\":true}", true));
                        black_box(tx.finish(ResponseOutcome {
                            status: 200,
                            headers: None,
                            error: None,
                        }))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // A blocked request logs at info level; the default `logging.level`.
    for (name, level) in [
        ("log_off", log::LevelFilter::Off),
        ("log_info", log::LevelFilter::Info),
    ] {
        group.bench_function(BenchmarkId::new("request_headers/blocked", name), |b| {
            log::set_max_level(level);
            b.iter_batched(
                blocked_ip,
                |req| {
                    let mut tx = base.transaction();
                    black_box(tx.request_headers(req))
                },
                BatchSize::SmallInput,
            );
            log::set_max_level(log::LevelFilter::Off);
        });
    }
    group.finish();
}

/// `Transaction::new` clones the list matchers, and `IpListMatcher::clone`
/// deep-copies its raw CIDR strings.
fn new_transaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction/new");
    for entries in [2usize, 1_000, 10_000] {
        let blocked = (0..entries)
            .map(|i| format!("10.{}.{}.0/24", i / 250, i % 250))
            .collect();
        let waf = waf(&Opts {
            blocked_ips: Some(blocked),
            ..Opts::default()
        });
        group.bench_with_input(
            BenchmarkId::new("ip_list_entries", entries),
            &waf,
            |b, waf| b.iter(|| black_box(waf.transaction())),
        );
    }
    group.finish();
}

/// `finish` runs on every request; only matched ones write an audit entry.
fn finish(c: &mut Criterion) {
    let base = waf(&Opts::default());
    let headers = response_headers();
    let outcome = || ResponseOutcome {
        status: 200,
        headers: Some(&headers),
        error: None,
    };

    let mut group = c.benchmark_group("finish");
    group.bench_function("unmatched", |b| {
        b.iter_batched(
            || {
                let mut tx = base.transaction();
                tx.set_request(benign());
                tx
            },
            |mut tx| black_box(tx.finish(outcome())),
            BatchSize::SmallInput,
        )
    });
    for (name, text_audit) in [("audit_json", false), ("audit_text", true)] {
        let waf = waf(&Opts {
            log_every_request: true,
            text_audit,
            ..Opts::default()
        });
        group.bench_function(name, |b| {
            b.iter_batched(
                || {
                    let mut tx = waf.transaction();
                    tx.request_headers(benign());
                    tx
                },
                |mut tx| black_box(tx.finish(outcome())),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Body bytes are copied into the inspection buffer, the pending buffer and
/// the `http.request.body.raw` field; multipart parsing adds another copy
/// and runs whether or not a rule reads the parts.
fn body(c: &mut Criterion) {
    const CHUNK: usize = 16 * 1024;
    let size = 256 * 1024;
    let json = json_body(size);
    let (multipart_ct, multipart) = multipart_body(4, size / 4);

    let with_rules = waf(&Opts {
        body_rule: true,
        ..Opts::default()
    });
    let without_rules = waf(&Opts::default());
    let inspecting = waf(&Opts {
        inspect_response_body: true,
        ..Opts::default()
    });

    let mut group = c.benchmark_group("body");
    group.throughput(Throughput::Bytes(size as u64));
    for (name, waf) in [
        ("body_rules", &with_rules),
        ("no_body_rules", &without_rules),
    ] {
        group.bench_with_input(
            BenchmarkId::new("request/json_256k", name),
            waf,
            |b, waf| {
                b.iter_batched(
                    || {
                        let mut tx = waf.transaction();
                        tx.request_headers(post_json());
                        tx
                    },
                    |mut tx| {
                        for chunk in json.chunks(CHUNK) {
                            black_box(tx.request_body_chunk(chunk, false));
                        }
                        black_box(tx.request_body_chunk(b"", true))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.bench_function("request/multipart_256k/body_rules", |b| {
        b.iter_batched(
            || {
                let mut tx = with_rules.transaction();
                tx.request_headers(with_header(
                    post_json(),
                    "content-type",
                    Some(&multipart_ct),
                ));
                tx
            },
            |mut tx| {
                for chunk in multipart.chunks(CHUNK) {
                    black_box(tx.request_body_chunk(chunk, false));
                }
                black_box(tx.request_body_chunk(b"", true))
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("response/json_256k/inspect_no_rules", |b| {
        b.iter_batched(
            || {
                let mut tx = inspecting.transaction();
                tx.request_headers(benign());
                tx.response_headers(ResponseData {
                    status: 200,
                    headers: response_headers(),
                });
                tx
            },
            |mut tx| {
                for chunk in json.chunks(CHUNK) {
                    black_box(tx.response_body_chunk(chunk, false));
                }
                black_box(tx.response_body_chunk(b"", true))
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

/// Candidate replacements for the population helpers.
mod alt {
    use super::*;

    pub fn map_of_arrays(
        pairs: &[(String, String)],
    ) -> TypedMap<'static, TypedArray<'static, WfBytes<'static>>> {
        let mut groups: HashMap<&str, TypedArray<'static, WfBytes<'static>>> =
            HashMap::with_capacity(pairs.len());
        for (k, v) in pairs {
            groups
                .entry(k.as_str())
                .or_default()
                .push(WfBytes::from(v.as_bytes().to_vec()));
        }
        let mut map = TypedMap::new();
        for (k, values) in groups {
            map.insert(k.as_bytes().into(), values);
        }
        map
    }

    pub fn split_pairs(pairs: &[(String, String)]) -> (Vec<String>, Vec<String>) {
        let mut seen = HashSet::with_capacity(pairs.len());
        let names = pairs
            .iter()
            .filter(|(k, _)| seen.insert(k.as_str()))
            .map(|(k, _)| k.clone())
            .collect();
        let values = pairs.iter().map(|(_, v)| v.clone()).collect();
        (names, values)
    }

    pub fn cookies(header: &str) -> Vec<(String, String)> {
        header
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect()
    }
}

/// `populate::split_pairs` is crate-private; this mirrors it.
fn current_split_pairs(pairs: &[(String, String)]) -> (Vec<String>, Vec<String>) {
    let names: Vec<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
    let mut seen = HashSet::with_capacity(names.len());
    let names = names
        .into_iter()
        .filter(|s| seen.insert(s.clone()))
        .collect();
    let values = pairs.iter().map(|(_, v)| v.clone()).collect();
    (names, values)
}

fn current_cookies(header: &str) -> Vec<(String, String)> {
    cookie::Cookie::split_parse(header)
        .filter_map(Result::ok)
        .map(|c| (c.name().to_string(), c.value().to_string()))
        .collect()
}

fn populate_fields(c: &mut Criterion) {
    let sch = scheme::build(&["sqli".into(), "xss".into()], &[]);
    let (ip_lists, bytes_lists) = lists::build_from_config(&[]).unwrap();
    let req = benign();
    let cookie_header = populate::get_header(&req.headers, "cookie").unwrap();

    let mut group = c.benchmark_group("populate");
    group.bench_function("request_fields", |b| {
        b.iter_batched(
            benign,
            |req| {
                let mut ctx = scheme::new_context(&sch);
                lists::install(&mut ctx, &sch, &ip_lists, &bytes_lists);
                populate::request_fields(&mut ctx, &sch, &req);
                black_box(ctx)
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("new_context+lists", |b| {
        b.iter(|| {
            let mut ctx = scheme::new_context(&sch);
            lists::install(&mut ctx, &sch, &ip_lists, &bytes_lists);
            black_box(ctx)
        })
    });
    group.bench_function("headers_map/current", |b| {
        b.iter(|| {
            black_box(populate::owned_map_of_arrays(
                req.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            ))
        })
    });
    group.bench_function("headers_map/group_once", |b| {
        b.iter(|| black_box(alt::map_of_arrays(&req.headers)))
    });
    group.bench_function("split_pairs/current", |b| {
        b.iter(|| black_box(current_split_pairs(&req.headers)))
    });
    group.bench_function("split_pairs/dedup_borrowed", |b| {
        b.iter(|| black_box(alt::split_pairs(&req.headers)))
    });
    group.bench_function("cookies/cookie_crate", |b| {
        b.iter(|| black_box(current_cookies(cookie_header)))
    });
    group.bench_function("cookies/split", |b| {
        b.iter(|| black_box(alt::cookies(cookie_header)))
    });
    group.finish();
}

/// Individual expressions on a populated context: the cost of a rule.
fn expressions(c: &mut Criterion) {
    let config = WafConfig::from_yaml(&config(&Opts::default())).unwrap();
    let sch = scheme::build(&config.scores, &[]);
    let (ip_lists, bytes_lists) = lists::build_from_config(&config.lists).unwrap();
    let mut ctx = scheme::new_context(&sch);
    lists::install(&mut ctx, &sch, &ip_lists, &bytes_lists);
    populate::request_fields(&mut ctx, &sch, &benign());
    let json: String = (0..2000)
        .map(|i| format!("\"k{i}\":\"value-{i}\""))
        .collect::<Vec<_>>()
        .join(",");
    let json = format!("{{{json}}}");
    populate::body_fields(
        &mut ctx,
        &sch,
        json.as_bytes(),
        json.len(),
        false,
        Some("application/json"),
    );

    let cases = [
        ("path_eq", r#"http.request.uri.path == "/admin""#),
        ("ip_list", "ip.src in $blocked_ips"),
        ("ua_substring_list", "http.user_agent in $scanner_ua"),
        (
            "lower_matches",
            r#"lower(http.request.uri.path) matches "\.(php|asp|jsp)$""#,
        ),
        (
            "sqli_args",
            "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))",
        ),
        (
            "xss_args",
            "any(detect_xss(url_decode_uni(http.request.uri.args.values[*])))",
        ),
        (
            "sqli_cookies",
            "any(detect_sqli(url_decode_uni(http.request.cookies.values[*])))",
        ),
        (
            "header_lookup",
            r#"http.request.headers["x-request-id"][0] != """#,
        ),
        (
            "json_lookup",
            r#"lookup_json_string(http.request.uri.query, "a") == "b""#,
        ),
        // Each lookup parses the whole body again.
        (
            "json_lookup_body_64k/1",
            r#"lookup_json_string(http.request.body.raw, "k1999") == "x""#,
        ),
        (
            "json_lookup_body_64k/5",
            r#"lookup_json_string(http.request.body.raw, "k1") == "x" or lookup_json_string(http.request.body.raw, "k2") == "x" or lookup_json_string(http.request.body.raw, "k3") == "x" or lookup_json_string(http.request.body.raw, "k4") == "x" or lookup_json_string(http.request.body.raw, "k5") == "x""#,
        ),
        // `except` copies the whole map before the lookup.
        (
            "except_headers",
            r#"has_key(except(http.request.headers, "accept"), "x")"#,
        ),
        // Two owned copies of every value, although neither transform changes them.
        (
            "transform_chain_args",
            r#"any(url_decode_uni(lower(http.request.uri.args.values))[*] == "zzz")"#,
        ),
    ];
    let mut group = c.benchmark_group("expression");
    for (name, expr) in cases {
        let filter = sch.parse(expr).unwrap().compile();
        group.bench_function(name, |b| {
            b.iter(|| black_box(filter.execute(&ctx).unwrap()))
        });
    }
    group.finish();
}

fn jwt(c: &mut Criterion) {
    let config = WafConfig::from_yaml(&config(&Opts {
        jwt_and_schema: true,
        ..Opts::default()
    }))
    .unwrap();
    let sch = scheme::build(&config.scores, &["api".into()]);
    let jwt = JwtValidator::new(&config.token_configurations, &sch).unwrap();
    let valid = format!("Bearer {}", valid_token());
    let cases = [
        ("no_token", None),
        ("valid_hs256", Some(valid.as_str())),
        (
            "bad_signature",
            Some("Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0.e30.x"),
        ),
    ];

    let mut group = c.benchmark_group("jwt");
    for (name, authorization) in cases {
        let mut ctx = scheme::new_context(&sch);
        let req = with_header(benign(), "authorization", authorization);
        populate::request_fields(&mut ctx, &sch, &req);
        group.bench_function(BenchmarkId::new("evaluate", name), |b| {
            b.iter(|| black_box(jwt.evaluate(&ctx)))
        });
        group.bench_function(BenchmarkId::new("evaluate+fields", name), |b| {
            b.iter(|| {
                let outcomes = jwt.evaluate(&ctx);
                populate::jwt_fields(&mut ctx, &sch, &outcomes);
            })
        });
    }
    group.finish();
}

/// Schema validation of the request line and parameters, and of a body.
fn schema(c: &mut Criterion) {
    let config = WafConfig::from_yaml(&config(&Opts {
        jwt_and_schema: true,
        ..Opts::default()
    }))
    .unwrap();
    let schemas = SchemaValidator::new(&config.schemas).unwrap();
    let json = json_body(1024);
    let post = post_json();
    let (Some(post_request), _) = schemas.check_request(&post).unwrap() else {
        panic!("POST /api/v1/pets should match");
    };

    let mut group = c.benchmark_group("schema");
    for (name, make) in [
        ("matched", benign as fn() -> RequestData),
        ("unmatched", attack),
    ] {
        let req = make();
        group.bench_function(BenchmarkId::new("check_request", name), |b| {
            b.iter(|| black_box(schemas.check_request(&req)))
        });
    }
    group.bench_function("check_body/json_1k", |b| {
        b.iter(|| {
            black_box(schemas.check_body(&post_request, Some("application/json"), &json, false))
        })
    });

    // The pieces of a matched request, as the openapi crate exposes them.
    let spec = CompiledSpec::from_yaml(PETSTORE).unwrap();
    let query = "limit=10&sort=name&page=2&fields=name,age&include=owner";
    let headers = benign().headers;
    group.bench_function("openapi/match_operation", |b| {
        b.iter(|| black_box(spec.match_operation("GET", "/api/v1/pets/42")))
    });
    let Match::Operation(op) = spec.match_operation("GET", "/api/v1/pets") else {
        panic!("GET /api/v1/pets should match");
    };
    group.bench_function("openapi/validate_parameters", |b| {
        b.iter(|| black_box(op.validate_parameters(Some(query), &headers)))
    });
    group.bench_function("openapi/undeclared_query_parameters", |b| {
        b.iter(|| black_box(op.undeclared_query_parameters(query)))
    });
    group.finish();
}

fn ratelimit(c: &mut Criterion) {
    const THREADS: u64 = 8;
    let store = MemoryStore::new();
    let key = |n: u64| {
        let mut key = RateLimitKey::new();
        key.push(format!("192.0.2.{n}"));
        key
    };

    let mut group = c.benchmark_group("ratelimit");
    for (name, timeout) in [("no_mitigation", 0), ("mitigation_60s", 60)] {
        let limits = Limits {
            period: Duration::from_secs(60),
            requests_per_period: u64::MAX,
            mitigation_timeout: Duration::from_secs(timeout),
        };
        let single = key(1);
        group.bench_function(BenchmarkId::new("single_thread", name), |b| {
            b.iter(|| black_box(store.check_and_incr(name, &single, &limits)))
        });
        // Each thread has its own key; wall time per request shows how the
        // store's locks scale.
        group.bench_function(BenchmarkId::new("8_threads", name), |b| {
            b.iter_custom(|iters| {
                let per_thread = iters.div_ceil(THREADS);
                let start = Instant::now();
                std::thread::scope(|s| {
                    for t in 0..THREADS {
                        let key = key(t);
                        let store = &store;
                        s.spawn(move || {
                            for _ in 0..per_thread {
                                black_box(store.check_and_incr(name, &key, &limits));
                            }
                        });
                    }
                });
                start.elapsed()
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    transaction,
    new_transaction,
    finish,
    body,
    populate_fields,
    expressions,
    jwt,
    schema,
    ratelimit
);
criterion_main!(benches);
