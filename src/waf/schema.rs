use std::path::Path;

use log::debug;

use super::data::RequestData;
use super::openapi::{CompiledSpec, ErrorClass, Location, Match, Unmatched, Violation};
use crate::config;

struct Schema {
    name: String,
    /// Hostnames this schema describes; empty means every host.
    hosts: Vec<String>,
    spec: CompiledSpec,
}

/// Validates requests against the configured OpenAPI schemas.
pub struct SchemaValidator {
    schemas: Vec<Schema>,
}

impl std::fmt::Debug for SchemaValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.schemas.iter().map(|s| &s.name))
            .finish()
    }
}

/// What the request-headers step found for a request.
pub struct SchemaOutcome<'a> {
    /// The schema that applies to the request host.
    pub schema: &'a str,
    /// The matched operation's path template, or why nothing matched.
    pub operation: Result<&'a str, Unmatched>,
    /// Violations in the path, query, header and cookie parameters.
    pub violations: Vec<Violation>,
    pub undeclared_query_parameters: Vec<String>,
}

/// Enough of a matched request to validate its body once it arrives.
pub struct SchemaRequest {
    schema: usize,
    method: String,
    path: String,
}

impl SchemaValidator {
    pub fn new(configs: &[config::SchemaConfig]) -> Result<Self, Box<dyn std::error::Error>> {
        let schemas = configs
            .iter()
            .map(|cfg| {
                let spec = load_spec(&cfg.file)
                    .map_err(|e| format!("schema '{}': {}: {}", cfg.name, cfg.file.display(), e))?;
                Ok(Schema {
                    name: cfg.name.clone(),
                    hosts: cfg.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
                    spec,
                })
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;
        Ok(Self { schemas })
    }

    #[cfg(test)]
    pub(crate) fn from_specs(specs: Vec<(&str, &[&str], CompiledSpec)>) -> Self {
        Self {
            schemas: specs
                .into_iter()
                .map(|(name, hosts, spec)| Schema {
                    name: name.to_string(),
                    hosts: hosts.iter().map(|h| h.to_string()).collect(),
                    spec,
                })
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// Match the request to an operation and validate everything but the
    /// body. `None` when no schema applies to the request host.
    pub fn check_request(&self, req: &RequestData) -> Option<(SchemaRequest, SchemaOutcome<'_>)> {
        let host = host_name(&req.host);
        let (index, schema) = self
            .schemas
            .iter()
            .enumerate()
            .find(|(_, s)| s.hosts.is_empty() || s.hosts.contains(&host))?;

        let request = SchemaRequest {
            schema: index,
            method: req.method.clone(),
            path: percent_decode(&req.path),
        };
        let outcome = match schema.spec.match_operation(&request.method, &request.path) {
            Match::Operation(op) => {
                let query = (!req.query.is_empty()).then_some(req.query.as_str());
                SchemaOutcome {
                    schema: &schema.name,
                    operation: Ok(op.template),
                    violations: op.validate_parameters(query, &req.headers),
                    undeclared_query_parameters: op.undeclared_query_parameters(&req.query),
                }
            }
            Match::Unmatched(unmatched) => {
                debug!(
                    "schema '{}': no operation for {} {}: {:?}",
                    schema.name, request.method, request.path, unmatched
                );
                SchemaOutcome {
                    schema: &schema.name,
                    operation: Err(unmatched),
                    violations: Vec::new(),
                    undeclared_query_parameters: Vec::new(),
                }
            }
        };
        Some((request, outcome))
    }

    /// Validate the body of a request matched by [`Self::check_request`].
    /// `body` is the buffered body, `truncated` whether it exceeded the
    /// buffer, in which case it cannot be validated.
    pub fn check_body(
        &self,
        request: &SchemaRequest,
        content_type: Option<&str>,
        body: &[u8],
        truncated: bool,
    ) -> Vec<Violation> {
        let spec = &self.schemas[request.schema].spec;
        let Match::Operation(op) = spec.match_operation(&request.method, &request.path) else {
            return Vec::new();
        };
        if truncated {
            return vec![Violation::new(
                Location::Body,
                ErrorClass::BodySize,
                None,
                "",
                "Request body exceeds the inspection buffer",
            )];
        }
        op.validate_body(content_type, (!body.is_empty()).then_some(body))
    }
}

fn load_spec(path: &Path) -> Result<CompiledSpec, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let is_yaml = path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"));
    let spec = if is_yaml {
        CompiledSpec::from_yaml(&text)?
    } else {
        CompiledSpec::from_json(&text)?
    };
    Ok(spec)
}

/// The host without a port, lowercased.
fn host_name(host: &str) -> String {
    let name = match host.strip_prefix('[') {
        // `[::1]:8080`
        Some(rest) => rest.split_once(']').map_or(rest, |(ipv6, _)| ipv6),
        None => match host.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
            _ => host,
        },
    };
    name.to_ascii_lowercase()
}

/// Decode `%XX` escapes; invalid escapes and non-UTF-8 bytes are kept as
/// written so the path still fails to match rather than panicking.
fn percent_decode(path: &str) -> String {
    if !path.contains('%') {
        return path.to_string();
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::super::openapi::CompiledSpec;

    /// A pet store: `GET /pets?limit`, `POST /pets?dry_run` with a JSON body
    /// and `GET /pets/{id}`, served under `/v1`.
    pub const PETSTORE: &str = r#"
openapi: 3.1.0
info: {title: Pets, version: "1"}
servers: [{url: https://api.example.com/v1}]
paths:
  /pets:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, maximum: 100}}
        - {name: X-Tenant, in: header, required: true, schema: {type: string}}
      responses: {"200": {description: ok}}
    post:
      parameters:
        - {name: dry_run, in: query, schema: {type: boolean}}
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
      responses: {"201": {description: created}}
  /pets/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses: {"200": {description: ok}}
"#;

    pub fn petstore() -> CompiledSpec {
        CompiledSpec::from_yaml(PETSTORE).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::waf::populate::test_support::empty_request;

    fn validator() -> SchemaValidator {
        SchemaValidator::from_specs(vec![
            ("pets", &["api.example.com"], petstore()),
            ("any", &[], petstore()),
        ])
    }

    fn request(host: &str, method: &str, path: &str, query: &str) -> RequestData {
        let mut req = empty_request();
        req.host = host.into();
        req.method = method.into();
        req.path = path.into();
        req.query = query.into();
        req
    }

    fn targets(violations: &[Violation]) -> Vec<(Location, &str)> {
        let mut targets: Vec<_> = violations
            .iter()
            .map(|v| (v.location, v.target.as_str()))
            .collect();
        targets.sort();
        targets
    }

    #[test]
    fn schema_is_chosen_by_host() {
        let v = validator();
        let (_, outcome) = v
            .check_request(&request("API.example.com:8443", "GET", "/v1/pets/1", ""))
            .unwrap();
        assert_eq!(outcome.schema, "pets");
        let (_, outcome) = v
            .check_request(&request("other.example.com", "GET", "/v1/pets/1", ""))
            .unwrap();
        assert_eq!(
            outcome.schema, "any",
            "a schema without hosts takes the rest"
        );

        let only_pets =
            SchemaValidator::from_specs(vec![("pets", &["api.example.com"], petstore())]);
        assert!(
            only_pets
                .check_request(&request("other.example.com", "GET", "/v1/pets", ""))
                .is_none()
        );
    }

    #[test]
    fn matched_operation_reports_parameter_violations() {
        let v = validator();
        let mut req = request("api.example.com", "GET", "/v1/pets", "limit=500&page=2");
        req.headers.push(("cookie".into(), "a=1".into()));
        let (_, outcome) = v.check_request(&req).unwrap();
        assert_eq!(outcome.operation, Ok("/pets"));
        assert_eq!(
            targets(&outcome.violations),
            [(Location::Query, "limit"), (Location::Header, "X-Tenant")]
        );
        assert_eq!(outcome.violations[0].class, ErrorClass::ConstraintViolation);
        assert_eq!(outcome.violations[1].class, ErrorClass::MissingRequired);
        assert_eq!(outcome.undeclared_query_parameters, ["page"]);

        req.query = "limit=10".into();
        req.headers.push(("x-tenant".into(), "acme".into()));
        let (_, outcome) = v.check_request(&req).unwrap();
        assert!(outcome.violations.is_empty());
        assert!(outcome.undeclared_query_parameters.is_empty());
    }

    #[test]
    fn unmatched_path_and_method() {
        let v = validator();
        let (_, outcome) = v
            .check_request(&request("api.example.com", "GET", "/v1/owners", ""))
            .unwrap();
        assert_eq!(outcome.operation, Err(Unmatched::Path));
        let (_, outcome) = v
            .check_request(&request("api.example.com", "DELETE", "/v1/pets", ""))
            .unwrap();
        assert_eq!(
            outcome.operation,
            Err(Unmatched::Method {
                allowed: vec!["GET".into(), "POST".into()]
            })
        );
        // Outside the server base path nothing matches.
        let (_, outcome) = v
            .check_request(&request("api.example.com", "GET", "/pets", ""))
            .unwrap();
        assert_eq!(outcome.operation, Err(Unmatched::Path));
    }

    #[test]
    fn path_is_percent_decoded_before_matching() {
        let v = validator();
        let (_, outcome) = v
            .check_request(&request("api.example.com", "GET", "/v1/pets/%34%32", ""))
            .unwrap();
        assert_eq!(outcome.operation, Ok("/pets/{id}"));
        assert!(outcome.violations.is_empty());
        assert_eq!(percent_decode("/a%2Fb%zz%4"), "/a/b%zz%4");
    }

    #[test]
    fn body_is_validated_against_the_matched_operation() {
        let v = validator();
        let (request, _) = v
            .check_request(&request("api.example.com", "POST", "/v1/pets", ""))
            .unwrap();
        let json = Some("application/json");

        assert!(
            v.check_body(&request, json, br#"{"name": "Rex", "age": 3}"#, false)
                .is_empty()
        );

        let violations = v.check_body(&request, json, br#"{"name": "", "age": "3"}"#, false);
        assert_eq!(
            targets(&violations),
            [(Location::Body, "/age"), (Location::Body, "/name")]
        );

        let violations = v.check_body(&request, json, b"", false);
        assert_eq!(violations[0].class, ErrorClass::MissingRequired);
        assert_eq!(violations[0].target, "");

        let violations = v.check_body(&request, Some("text/plain"), b"Rex", false);
        assert_eq!(violations[0].class, ErrorClass::UnsupportedMediaType);

        let violations = v.check_body(&request, json, b"{\"name\": \"Rex\"", true);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].class, ErrorClass::BodySize);
    }

    #[test]
    fn host_names_drop_ports_and_case() {
        assert_eq!(host_name("API.Example.com:443"), "api.example.com");
        assert_eq!(host_name("[::1]:8080"), "::1");
        assert_eq!(host_name("localhost"), "localhost");
    }

    #[test]
    fn specs_load_from_yaml_and_json_files() {
        let dir = std::env::temp_dir().join(format!("openshield-schema-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let yaml = dir.join("pets.yaml");
        std::fs::write(&yaml, PETSTORE).unwrap();
        let json = dir.join("pets.json");
        let doc: serde_json::Value = serde_yaml::from_str(PETSTORE).unwrap();
        std::fs::write(&json, doc.to_string()).unwrap();
        let broken = dir.join("broken.json");
        std::fs::write(&broken, "{").unwrap();

        let cfg = |name: &str, file: &Path| config::SchemaConfig {
            name: name.into(),
            file: file.to_path_buf(),
            hosts: Vec::new(),
        };
        let v = SchemaValidator::new(&[cfg("y", &yaml), cfg("j", &json)]).unwrap();
        assert_eq!(v.schemas.len(), 2);

        let err = SchemaValidator::new(&[cfg("b", &broken)])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("schema 'b'") && err.contains("broken.json"),
            "{err}"
        );
        let err = SchemaValidator::new(&[cfg("m", &dir.join("missing.yaml"))])
            .unwrap_err()
            .to_string();
        assert!(err.contains("schema 'm'"), "{err}");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
