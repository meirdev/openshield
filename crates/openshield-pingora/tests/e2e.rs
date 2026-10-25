//! Runs the built proxy with `examples/config.yaml` in front of an echo
//! upstream and sends the requests the example README describes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use reqwest::StatusCode;

const JWT_SECRET: &[u8] = b"openshield-demo-secret-change-me!";

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A minimal HTTP/1.1 server answering every request with `200` and a JSON
/// echo, closing the connection after each response.
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || echo(stream));
        }
    });
    port
}

fn echo(mut stream: TcpStream) {
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
    reader.read_exact(&mut body).unwrap();

    let mut parts = request_line.split_whitespace();
    let payload = serde_json::json!({
        "method": parts.next().unwrap_or(""),
        "path": parts.next().unwrap_or(""),
        "body": String::from_utf8_lossy(&body),
    })
    .to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
}

/// The proxy process; killed when dropped, so a failing assertion does not
/// leave it running.
struct Proxy {
    child: Child,
    url: String,
    log_dir: PathBuf,
}

impl Proxy {
    fn start(upstream_port: u16) -> Self {
        let port = free_port();
        let dir =
            std::env::temp_dir().join(format!("openshield-e2e-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let examples = examples_dir();
        let config = std::fs::read_to_string(examples.join("config.yaml"))
            .unwrap()
            .replace("127.0.0.1:8080", &format!("127.0.0.1:{port}"))
            .replace("127.0.0.1:3000", &format!("127.0.0.1:{upstream_port}"))
            .replace(
                "./openapi/petstore.yaml",
                examples.join("openapi/petstore.yaml").to_str().unwrap(),
            );
        let config = format!(
            "{config}\npid_file: {dir}/openshield.pid\nupgrade_sock: {dir}/upgrade.sock\n",
            dir = dir.display()
        );
        let config_path = dir.join("config.yaml");
        std::fs::write(&config_path, config).unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_openshield"))
            .arg("-c")
            .arg(&config_path)
            .stdout(std::fs::File::create(dir.join("stdout.log")).unwrap())
            .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
            .spawn()
            .expect("proxy binary should start");
        let mut proxy = Self {
            child,
            url: format!("http://127.0.0.1:{port}"),
            log_dir: dir,
        };
        proxy.wait_until_listening(port);
        proxy
    }

    fn wait_until_listening(&mut self, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("proxy exited early with {status}\n{}", self.logs());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("proxy did not start listening\n{}", self.logs());
    }

    fn logs(&self) -> String {
        let read = |name| std::fs::read_to_string(self.log_dir.join(name)).unwrap_or_default();
        format!(
            "--- stdout ---\n{}--- stderr ---\n{}",
            read("stdout.log"),
            read("stderr.log")
        )
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.log_dir);
    }
}

fn token() -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("demo".into());
    let claims = serde_json::json!({"sub": "alice", "exp": get_current_timestamp() + 300});
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET)).unwrap()
}

/// Sends `request` and checks the status and that the body contains
/// `body_contains`: the configured message for blocked requests, part of
/// the upstream's echo for forwarded ones.
async fn expect(
    what: &str,
    request: reqwest::RequestBuilder,
    status: StatusCode,
    body_contains: &str,
) {
    let response = request
        .send()
        .await
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    let got = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(got, status, "{what}: unexpected status; body: {body}");
    assert!(
        body.contains(body_contains),
        "{what}: body {body:?} lacks {body_contains:?}"
    );
}

#[tokio::test]
async fn example_configuration_end_to_end() {
    let upstream = spawn_upstream();
    let proxy = Proxy::start(upstream);
    let client = reqwest::Client::new();
    let url = |path: &str| format!("{}{path}", proxy.url);
    let forwarded = StatusCode::OK;

    expect(
        "plain request",
        client.get(url("/")),
        forwarded,
        r#""path":"/""#,
    )
    .await;

    expect(
        "sqli in query",
        client.get(url("/search?q=1'%20OR%20'1'='1")),
        StatusCode::FORBIDDEN,
        "injection detected",
    )
    .await;
    expect(
        "xss in query",
        client.get(url("/search?q=<script>alert(1)</script>")),
        StatusCode::FORBIDDEN,
        "injection detected",
    )
    .await;
    expect(
        "benign query",
        client.get(url("/search?q=cats")),
        forwarded,
        r#""path":"/search?q=cats""#,
    )
    .await;

    expect(
        "scanner user agent",
        client
            .get(url("/"))
            .header("user-agent", "Mozilla sqlmap/1.7"),
        StatusCode::FORBIDDEN,
        "scanner blocked",
    )
    .await;

    for attempt in 1..=5 {
        expect(
            &format!("login attempt {attempt}"),
            client.post(url("/login")),
            forwarded,
            r#""method":"POST""#,
        )
        .await;
    }
    expect(
        "sixth login attempt",
        client.post(url("/login")),
        StatusCode::TOO_MANY_REQUESTS,
        "too many login attempts",
    )
    .await;
    expect(
        "other paths are not rate limited",
        client.post(url("/logout")),
        forwarded,
        "",
    )
    .await;

    expect(
        "private api without token",
        client.get(url("/api/private/profile")),
        StatusCode::UNAUTHORIZED,
        "valid token required",
    )
    .await;
    expect(
        "private api with garbage token",
        client
            .get(url("/api/private/profile"))
            .bearer_auth("not.a.jwt"),
        StatusCode::UNAUTHORIZED,
        "valid token required",
    )
    .await;
    expect(
        "private api with token",
        client.get(url("/api/private/profile")).bearer_auth(token()),
        forwarded,
        r#""path":"/api/private/profile""#,
    )
    .await;

    expect(
        "valid api query",
        client.get(url("/api/v1/pets?limit=10")),
        forwarded,
        "",
    )
    .await;
    expect(
        "query above maximum",
        client.get(url("/api/v1/pets?limit=500")),
        StatusCode::BAD_REQUEST,
        "request does not match the API schema",
    )
    .await;
    expect(
        "path parameter of the wrong type",
        client.get(url("/api/v1/pets/rex")),
        StatusCode::BAD_REQUEST,
        "request does not match the API schema",
    )
    .await;
    expect(
        "unknown api endpoint",
        client.get(url("/api/v1/owners")),
        StatusCode::NOT_FOUND,
        "unknown endpoint",
    )
    .await;
    expect(
        "valid api body",
        client
            .post(url("/api/v1/pets"))
            .header("content-type", "application/json")
            .body(r#"{"name":"Rex","species":"dog"}"#),
        forwarded,
        r#"\"name\":\"Rex\""#,
    )
    .await;
    expect(
        "api body missing a required property",
        client
            .post(url("/api/v1/pets"))
            .header("content-type", "application/json")
            .body(r#"{"species":"dragon"}"#),
        StatusCode::BAD_REQUEST,
        "body does not match the API schema",
    )
    .await;
    expect(
        "api body with the wrong media type",
        client
            .post(url("/api/v1/pets"))
            .header("content-type", "text/plain")
            .body("Rex"),
        StatusCode::BAD_REQUEST,
        "body does not match the API schema",
    )
    .await;

    // The blocks above should have produced audit records.
    let logs = proxy.logs();
    assert!(logs.contains("rules: scanners:block"), "{logs}");
    assert!(
        logs.contains("rules: sqli-args:score, block-injection:block"),
        "{logs}"
    );
}
