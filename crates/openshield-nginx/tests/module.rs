//! Loads the built module into nginx in front of an echo upstream and sends
//! requests through it.
//!
//! Needs the module built first, since `cargo test` does not rebuild a
//! cdylib, and an nginx binary: `OPENSHIELD_NGINX_BIN`, or the one the
//! `vendored` feature builds. `make nginx-test` does both steps.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const WAF_CONFIG: &str = r#"
audit_log:
  path: audit.log
lists:
  - name: scanner_ua
    kind: substring
    items: ["sqlmap", "nikto"]
challenge:
  turnstile_site_key: site
  turnstile_secret_key: secret
  cookie_secret: cookie
rulesets:
  - name: main
    kind: root
    rules:
      - id: admin
        action: block
        expression: 'http.request.uri.path == "/admin"'
        action_parameters:
          response: {status_code: 418, content_type: "text/plain", content: "nope"}
      - id: scanners
        action: block
        expression: 'http.user_agent in $scanner_ua'
      - id: logged
        action: log
        expression: 'http.request.uri.path == "/logged"'
      - id: challenge
        action: challenge
        expression: 'http.request.uri.path == "/challenge"'
      - id: evil-body
        phase: request_body
        action: block
        expression: 'http.request.body.raw contains "evil"'
        action_parameters:
          response: {status_code: 422, content: "bad body"}
"#;

/// Response inspection: a header-phase log rule and a body-phase block.
const RESPONSE_CONFIG: &str = r#"
audit_log:
  path: audit.log
inspect_response_body: true
rulesets:
  - name: main
    kind: root
    rules:
      - id: resp-ok
        phase: response_headers
        action: log
        expression: 'http.response.code == 200'
      - id: secret
        phase: response_body
        action: block
        expression: 'http.response.body.raw contains "secret"'
        action_parameters:
          response: {content: "redacted"}
"#;

/// Three requests per minute to `/limited`, per client address.
const RATELIMIT_CONFIG: &str = r#"
audit_log:
  path: audit.log
rulesets:
  - name: main
    kind: root
    rules:
      - id: limited
        action: block
        expression: 'http.request.uri.path == "/limited"'
        ratelimit:
          characteristics: [ip.src]
          period: 60
          requests_per_period: 3
        action_parameters:
          response: {status_code: 429, content: "slow down"}
"#;

fn module_path() -> PathBuf {
    // target/debug/deps/module-<hash> -> target/debug/libopenshield_nginx.so
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap();
    let so = dir.join("libopenshield_nginx.so");
    let hint = "build it first: cargo build -p openshield-nginx --features vendored";
    assert!(so.exists(), "module not built ({hint}): {}", so.display());

    // `cargo test` does not rebuild the cdylib; refuse to test stale code.
    let built = std::fs::metadata(&so).unwrap().modified().unwrap();
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(&src).unwrap().flatten() {
        let modified = entry.metadata().unwrap().modified().unwrap();
        assert!(
            modified <= built,
            "{} is newer than the built module; {hint}",
            entry.path().display()
        );
    }
    so
}

fn nginx_binary() -> PathBuf {
    if let Ok(bin) = std::env::var("OPENSHIELD_NGINX_BIN") {
        return PathBuf::from(bin);
    }
    let Some(build_dir) = option_env!("DEP_NGINX_BUILD_DIR") else {
        panic!("set OPENSHIELD_NGINX_BIN, or build with --features vendored");
    };
    let bin = PathBuf::from(build_dir).join("nginx");
    assert!(bin.exists(), "no nginx binary at {}", bin.display());
    bin
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Answers every request with `200` and `echo:<method> <uri> len=<body bytes>`.
/// Paths under `/slow` get the body in two writes with a pause between them.
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    return;
                }
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; content_length];
                let _ = reader.read_exact(&mut body);
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let uri = parts.next().unwrap_or("");
                let mut stream = stream;
                if uri == "/siteverify" {
                    // Stand-in for Turnstile's siteverify: `good-token` passes.
                    let form = String::from_utf8_lossy(&body);
                    let json = format!(
                        r#"{{"success":{},"form":"{}"}}"#,
                        form.contains("response=good-token"),
                        form
                    );
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(),
                        json
                    );
                    return;
                }
                let echo = format!("echo:{method} {uri} len={}", body.len());
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    echo.len()
                );
                if echo.contains(" /slow") {
                    let (a, b) = echo.split_at(echo.len() / 2);
                    let _ = stream.write_all(a.as_bytes());
                    let _ = stream.flush();
                    std::thread::sleep(Duration::from_millis(100));
                    let _ = stream.write_all(b.as_bytes());
                } else {
                    let _ = stream.write_all(echo.as_bytes());
                }
            });
        }
    });
    port
}

struct Nginx {
    child: Child,
    prefix: PathBuf,
    port: u16,
    /// Running with a master and workers: stop with TERM so they all exit.
    master: bool,
}

impl Nginx {
    fn start() -> Self {
        Self::start_with(WAF_CONFIG)
    }

    fn start_with(waf_config: &str) -> Self {
        Self::start_full(waf_config, None, None)
    }

    /// `verify_pass` overrides where the Turnstile location proxies to; the
    /// default is the echo upstream's stand-in. `workers` runs a master with
    /// that many worker processes instead of a single process.
    fn start_full(waf_config: &str, verify_pass: Option<&str>, workers: Option<u32>) -> Self {
        // Tests run in parallel in one process, so the pid alone is not unique.
        static INSTANCE: AtomicUsize = AtomicUsize::new(0);
        let instance = INSTANCE.fetch_add(1, Ordering::Relaxed);
        let prefix = std::env::temp_dir().join(format!(
            "openshield-nginx-{}-{instance}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&prefix);
        std::fs::create_dir_all(prefix.join("logs")).unwrap();
        std::fs::create_dir_all(prefix.join("conf")).unwrap();
        std::fs::write(prefix.join("conf/waf.yaml"), waf_config).unwrap();

        let port = free_port();
        let upstream = spawn_upstream();
        let verify = verify_pass
            .map(str::to_string)
            .unwrap_or_else(|| format!("proxy_pass http://127.0.0.1:{upstream}/siteverify;"));
        let processes = match workers {
            Some(n) => format!("master_process on;\nworker_processes {n};"),
            None => "master_process off;".to_string(),
        };
        let conf = format!(
            r#"
load_module {module};
daemon off;
{processes}
pid logs/nginx.pid;
error_log logs/error.log info;
events {{ worker_connections 64; }}
http {{
    openshield_config conf/waf.yaml;
    openshield_turnstile_location /_openshield/turnstile;
    client_body_buffer_size 1k;
    log_format waf '$status $openshield_action $openshield_rules $openshield_request_id';
    access_log logs/access.log waf;
    server {{
        listen 127.0.0.1:{port};
        location / {{
            openshield on;
            proxy_pass http://127.0.0.1:{upstream};
        }}
        location /off/ {{
            openshield off;
            proxy_pass http://127.0.0.1:{upstream};
        }}
        location = /_openshield/turnstile {{
            internal;
            {verify}
        }}
    }}
}}
"#,
            module = module_path().display(),
        );
        std::fs::write(prefix.join("conf/nginx.conf"), conf).unwrap();

        let child = Command::new(nginx_binary())
            .arg("-p")
            .arg(&prefix)
            .arg("-c")
            .arg("conf/nginx.conf")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start nginx");
        let nginx = Self {
            child,
            prefix,
            port,
            master: workers.is_some(),
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "nginx did not start:\n{}",
                nginx.error_log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        nginx
    }

    fn error_log(&self) -> String {
        std::fs::read_to_string(self.prefix.join("logs/error.log")).unwrap_or_default()
    }

    fn access_log(&self) -> String {
        std::fs::read_to_string(self.prefix.join("logs/access.log")).unwrap_or_default()
    }

    fn audit_log(&self) -> String {
        std::fs::read_to_string(self.prefix.join("audit.log")).unwrap_or_default()
    }

    fn get(&self, path: &str, headers: &[(&str, &str)]) -> (u16, Vec<(String, String)>, String) {
        self.request("GET", path, headers, b"")
    }

    fn post(&self, path: &str, body: &[u8]) -> (u16, Vec<(String, String)>, String) {
        self.request("POST", path, &[("Content-Type", "text/plain")], body)
    }

    /// The POST the challenge page makes.
    fn verify(&self, form: &str) -> (u16, Vec<(String, String)>, String) {
        self.request(
            "POST",
            "/__openshield/challenge",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            form.as_bytes(),
        )
    }

    /// One HTTP/1.1 request; returns status, headers (lowercased names) and
    /// body.
    fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut req =
            format!("{method} {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n");
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        let mut req = req.into_bytes();
        req.extend_from_slice(body);
        stream.write_all(&req).unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = raw.split_once("\r\n\r\n").expect("response head");
        let mut lines = head.lines();
        let status: u16 = lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let body = if header(&headers, "transfer-encoding") == Some("chunked") {
            dechunk(body)
        } else {
            body.to_string()
        };
        (status, headers, body)
    }
}

impl Nginx {
    /// `nginx -s reload`, then wait for the new workers to listen.
    fn reload(&self) {
        let _ = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status();
        std::thread::sleep(Duration::from_millis(500));
    }
}

impl Drop for Nginx {
    fn drop(&mut self) {
        if self.master {
            let _ = Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status();
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::env::var_os("OPENSHIELD_KEEP_TMP").is_none() {
            let _ = std::fs::remove_dir_all(&self.prefix);
        }
    }
}

/// Decode a chunked transfer-encoded body.
fn dechunk(mut raw: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = raw.split_once("\r\n") {
        let size = usize::from_str_radix(size.trim(), 16).expect("chunk size");
        if size == 0 {
            break;
        }
        out.push_str(&rest[..size]);
        raw = &rest[size + 2..];
    }
    out
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn wait_for<F: Fn() -> bool>(what: &str, f: F) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn module_blocks_logs_and_passes_through() {
    let nginx = Nginx::start();

    // Forwarded to the upstream.
    let (status, _, body) = nginx.get("/hello", &[]);
    assert_eq!(
        (status, body.as_str()),
        (200, "echo:GET /hello len=0"),
        "{}",
        nginx.error_log()
    );

    // Blocked by a rule with a custom response.
    let (status, headers, body) = nginx.get("/admin", &[]);
    assert_eq!(status, 418);
    assert_eq!(header(&headers, "content-type"), Some("text/plain"));
    assert_eq!(body, "nope");

    // Blocked by a list match, with the default 403.
    let (status, _, _) = nginx.get("/", &[("User-Agent", "sqlmap/1.7")]);
    assert_eq!(status, 403);

    // The challenge page is served without a cookie.
    let (status, headers, body) = nginx.get("/challenge", &[]);
    assert_eq!(status, 403);
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(header(&headers, "cache-control"), Some("no-store"));
    assert!(body.contains("<html"), "{body}");

    // A log rule records but does not interfere.
    let (status, _, _) = nginx.get("/logged", &[]);
    assert_eq!(status, 200);

    // `openshield off` locations are not inspected, even for blocked paths.
    let (status, _, body) = nginx.get("/off/admin", &[]);
    assert_eq!((status, body.as_str()), (200, "echo:GET /off/admin len=0"));

    // Variables in the access log, one line per request in order.
    wait_for("six access log lines", || {
        nginx.access_log().lines().count() >= 6
    });
    let log = nginx.access_log();
    let lines: Vec<Vec<&str>> = log.lines().map(|l| l.split(' ').collect()).collect();
    assert_eq!(lines[0][..2], ["200", "pass"]);
    assert_eq!(lines[1][..3], ["418", "block", "admin"]);
    assert_eq!(lines[2][..3], ["403", "block", "scanners"]);
    assert_eq!(lines[3][..3], ["403", "challenge", "challenge"]);
    assert_eq!(lines[4][..3], ["200", "pass", "logged"]);
    assert_eq!(lines[5][..4], ["200", "-", "-", "-"]);
    for line in &lines[..5] {
        assert_eq!(line[3].len(), 36, "request id is a uuid: {line:?}");
    }

    // Audit entries for the requests on which rules matched.
    wait_for("audit entries", || nginx.audit_log().lines().count() >= 4);
    let audit: Vec<serde_json::Value> = nginx
        .audit_log()
        .lines()
        .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
        .collect();
    assert_eq!(audit.len(), 4);
    assert_eq!(audit[0]["waf_action"], "block");
    assert_eq!(audit[0]["request"]["path"], "/admin");
    assert_eq!(audit[0]["request"]["host"], "example.test");
    assert_eq!(audit[0]["response"]["status"], 418);
    assert_eq!(audit[3]["waf_action"], "pass");
    assert_eq!(audit[3]["waf_matched_rules"][0]["id"], "logged");

    assert!(
        !nginx.error_log().contains("[error]") && !nginx.error_log().contains("[emerg]"),
        "{}",
        nginx.error_log()
    );
}

#[test]
fn request_bodies_are_inspected() {
    let nginx = Nginx::start();

    // A clean body reaches the upstream intact.
    let (status, _, body) = nginx.post("/submit", b"hello there");
    assert_eq!(
        (status, body.as_str()),
        (200, "echo:POST /submit len=11"),
        "{}",
        nginx.error_log()
    );

    // A body matching a request_body rule is blocked with the rule's response.
    let (status, _, body) = nginx.post("/submit", b"something evil");
    assert_eq!((status, body.as_str()), (422, "bad body"));

    // Larger than client_body_buffer_size: nginx spills it to a temp file,
    // which is read back for inspection.
    let mut big = vec![b'x'; 8 * 1024];
    big.extend_from_slice(b"...evil");
    let (status, _, body) = nginx.post("/submit", &big);
    assert_eq!((status, body.as_str()), (422, "bad body"));
    let big_clean = vec![b'x'; 8 * 1024];
    let (status, _, body) = nginx.post("/submit", &big_clean);
    assert_eq!((status, body.as_str()), (200, "echo:POST /submit len=8192"));

    // Header rules still apply before the body is read.
    let (status, _, body) = nginx.post("/admin", b"anything");
    assert_eq!((status, body.as_str()), (418, "nope"));

    wait_for("five access log lines", || {
        nginx.access_log().lines().count() >= 5
    });
    let log = nginx.access_log();
    let lines: Vec<Vec<&str>> = log.lines().map(|l| l.split(' ').collect()).collect();
    assert_eq!(lines[0][..2], ["200", "pass"]);
    assert_eq!(lines[1][..3], ["422", "block", "evil-body"]);
    assert_eq!(lines[2][..3], ["422", "block", "evil-body"]);
    assert_eq!(lines[3][..2], ["200", "pass"]);
    assert_eq!(lines[4][..3], ["418", "block", "admin"]);

    wait_for("audit entries", || nginx.audit_log().lines().count() >= 3);
    let first: serde_json::Value =
        serde_json::from_str(nginx.audit_log().lines().next().unwrap()).unwrap();
    assert_eq!(first["request"]["body"], "something evil");
    assert_eq!(first["request"]["body_size"], 14);

    assert!(
        !nginx.error_log().contains("[error]") && !nginx.error_log().contains("[emerg]"),
        "{}",
        nginx.error_log()
    );
}

#[test]
fn response_headers_and_bodies_are_inspected() {
    let nginx = Nginx::start_with(RESPONSE_CONFIG);

    // Passed through unchanged.
    let (status, _, body) = nginx.get("/plain", &[]);
    assert_eq!(
        (status, body.as_str()),
        (200, "echo:GET /plain len=0"),
        "{}",
        nginx.error_log()
    );

    // The body matched a response_body rule: status and headers were already
    // sent, the body is replaced.
    let (status, _, body) = nginx.get("/secret-data", &[]);
    assert_eq!((status, body.as_str()), (200, "redacted"));

    // Streamed in two parts: the first is held, then released with the rest.
    let (status, _, body) = nginx.get("/slow/data", &[]);
    assert_eq!((status, body.as_str()), (200, "echo:GET /slow/data len=0"));

    // Streamed, and the match arrives in the second part.
    let (status, _, body) = nginx.get("/slow/secret", &[]);
    assert_eq!((status, body.as_str()), (200, "redacted"));

    wait_for("four access log lines", || {
        nginx.access_log().lines().count() >= 4
    });
    let log = nginx.access_log();
    let lines: Vec<Vec<&str>> = log.lines().map(|l| l.split(' ').collect()).collect();
    assert_eq!(lines[0][..3], ["200", "pass", "resp-ok"]);
    assert_eq!(lines[1][..3], ["200", "block", "resp-ok,secret"]);
    assert_eq!(lines[2][..3], ["200", "pass", "resp-ok"]);
    assert_eq!(lines[3][..3], ["200", "block", "resp-ok,secret"]);

    wait_for("audit entries", || nginx.audit_log().lines().count() >= 4);
    let audit: Vec<serde_json::Value> = nginx
        .audit_log()
        .lines()
        .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
        .collect();
    assert_eq!(audit[1]["waf_action"], "block");
    assert_eq!(audit[1]["response"]["status"], 200);
    assert_eq!(audit[1]["response"]["body"], "echo:GET /secret-data len=0");
    assert_eq!(audit[3]["response"]["body"], "echo:GET /slow/secret len=0");

    assert!(
        !nginx.error_log().contains("[error]")
            && !nginx.error_log().contains("[emerg]")
            && !nginx.error_log().contains("[alert]"),
        "{}",
        nginx.error_log()
    );
}

#[test]
fn challenge_verification_round_trip() {
    let nginx = Nginx::start();

    // A good token: cookie set, redirected back to where the visitor was.
    let (status, headers, _) = nginx.verify("cf-turnstile-response=good-token&redirect=/challenge");
    assert_eq!(status, 302, "{}", nginx.error_log());
    // nginx's default `absolute_redirect on` makes the Location absolute.
    assert!(
        header(&headers, "location").is_some_and(|l| l.ends_with("/challenge")),
        "{headers:?}"
    );
    assert_eq!(header(&headers, "cache-control"), Some("no-store"));
    let cookie = header(&headers, "set-cookie").expect("challenge cookie");
    let cookie = cookie.split(';').next().unwrap().to_string();

    // With the cookie the challenged path is served.
    let (status, _, body) = nginx.get("/challenge", &[("Cookie", &cookie)]);
    assert_eq!((status, body.as_str()), (200, "echo:GET /challenge len=0"));
    // Without it, still challenged.
    let (status, _, _) = nginx.get("/challenge", &[]);
    assert_eq!(status, 403);

    // A bad token or no token: the page again.
    for form in ["cf-turnstile-response=bad-token", "redirect=/x", ""] {
        let (status, headers, body) = nginx.verify(form);
        assert_eq!(status, 403, "form {form:?}");
        assert_eq!(
            header(&headers, "content-type"),
            Some("text/html; charset=utf-8")
        );
        assert!(body.contains("<html"), "{body}");
    }

    wait_for("access log lines", || {
        nginx.access_log().lines().count() >= 6
    });
    let log = nginx.access_log();
    let lines: Vec<Vec<&str>> = log.lines().map(|l| l.split(' ').collect()).collect();
    assert_eq!(lines[0][..2], ["302", "pass"]);
    // The challenge rule matched; the cookie turned the verdict into a pass.
    assert_eq!(lines[1][..3], ["200", "challenge", "challenge"]);
    assert_eq!(lines[2][..3], ["403", "challenge", "challenge"]);
    assert_eq!(lines[3][..2], ["403", "pass"]);

    assert!(
        !nginx.error_log().contains("[error]") && !nginx.error_log().contains("[emerg]"),
        "{}",
        nginx.error_log()
    );
}

/// Against Cloudflare itself. Opt in with `OPENSHIELD_TURNSTILE_SECRET` (and
/// optionally `OPENSHIELD_TURNSTILE_SITE_KEY`); a made-up token must come
/// back rejected through the real endpoint.
#[test]
fn challenge_verification_against_cloudflare() {
    let Ok(secret) = std::env::var("OPENSHIELD_TURNSTILE_SECRET") else {
        eprintln!("skipped: set OPENSHIELD_TURNSTILE_SECRET to test against Cloudflare");
        return;
    };
    let site_key = std::env::var("OPENSHIELD_TURNSTILE_SITE_KEY").unwrap_or_else(|_| "site".into());
    let config = WAF_CONFIG
        .replace(
            "turnstile_site_key: site",
            &format!("turnstile_site_key: \"{site_key}\""),
        )
        .replace(
            "turnstile_secret_key: secret",
            &format!("turnstile_secret_key: \"{secret}\""),
        );
    let nginx = Nginx::start_full(
        &config,
        Some(
            "proxy_pass https://challenges.cloudflare.com/turnstile/v0/siteverify;\n            \
             proxy_ssl_server_name on;\n            \
             proxy_set_header Host challenges.cloudflare.com;",
        ),
        None,
    );
    let (status, headers, body) = nginx.verify("cf-turnstile-response=not-a-real-token");
    assert_eq!(status, 403, "{}", nginx.error_log());
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(body.contains("<html"), "{body}");
    assert!(
        !nginx.error_log().contains("[error]"),
        "{}",
        nginx.error_log()
    );
}

#[test]
fn rate_limits_are_shared_between_workers() {
    // Four workers: counters kept per worker would let up to twelve through.
    let nginx = Nginx::start_full(RATELIMIT_CONFIG, None, Some(4));

    let statuses: Vec<u16> = (0..8).map(|_| nginx.get("/limited", &[]).0).collect();
    assert_eq!(
        statuses,
        [200, 200, 200, 429, 429, 429, 429, 429],
        "{}",
        nginx.error_log()
    );
    let (status, _, body) = nginx.get("/limited", &[]);
    assert_eq!((status, body.as_str()), (429, "slow down"));

    // Other paths are not limited.
    let (status, _, _) = nginx.get("/free", &[]);
    assert_eq!(status, 200);

    // Counts live in shared memory, so they survive a reload.
    nginx.reload();
    let (status, _, _) = nginx.get("/limited", &[]);
    assert_eq!(status, 429, "{}", nginx.error_log());

    assert!(
        !nginx.error_log().contains("[error]")
            && !nginx.error_log().contains("[emerg]")
            && !nginx.error_log().contains("[alert]"),
        "{}",
        nginx.error_log()
    );
}

#[test]
fn bad_config_fails_nginx_t() {
    let prefix = std::env::temp_dir().join(format!("openshield-nginx-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&prefix);
    std::fs::create_dir_all(prefix.join("logs")).unwrap();
    std::fs::create_dir_all(prefix.join("conf")).unwrap();
    std::fs::write(
        prefix.join("conf/waf.yaml"),
        "rulesets:\n  - name: main\n    kind: root\n    rules:\n      - id: r\n        action: block\n        expression: 'no.such.field == 1'\n",
    )
    .unwrap();
    std::fs::write(
        prefix.join("conf/nginx.conf"),
        format!(
            "load_module {};\nevents {{}}\nhttp {{ openshield_config conf/waf.yaml; }}\n",
            module_path().display()
        ),
    )
    .unwrap();
    let output = Command::new(nginx_binary())
        .arg("-t")
        .arg("-p")
        .arg(&prefix)
        .arg("-c")
        .arg("conf/nginx.conf")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("openshield_config") && stderr.contains("no.such.field"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&prefix);
}
