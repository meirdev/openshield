//! Validation of HTTP requests against an OpenAPI 3.0.x or 3.1.x document.
//!
//! A [`CompiledSpec`] is built once from the document. Per request,
//! [`CompiledSpec::match_operation`] finds the operation, then
//! [`MatchedOperation::validate_parameters`] checks the path, query, header
//! and cookie parameters and [`MatchedOperation::validate_body`] checks the
//! `Content-Type` and body. The two steps are separate because a proxy sees
//! the headers before the body. [`validate_request`] runs all of them.

mod body;
mod coerce;
mod content_type;
mod dialect;
pub mod error;
mod form;
mod params;
mod spec;
#[cfg(test)]
mod tests;
mod xml;

#[cfg(test)]
pub use error::ValidationResult;
pub use error::{ErrorClass, Location, Unmatched, Violation};
pub use spec::{CompiledOperation, CompiledSpec};

/// The outcome of looking up a request's operation.
pub enum Match<'s> {
    Operation(MatchedOperation<'s>),
    Unmatched(Unmatched),
}

/// An operation matched to a request path, ready to validate the request.
pub struct MatchedOperation<'s> {
    spec: &'s CompiledSpec,
    /// The OpenAPI path template that matched.
    pub template: &'s str,
    /// Path parameters captured from the request path, in template order.
    /// A `/` inside a value stays encoded as `%2F`.
    pub path_params: Vec<(&'s str, String)>,
    pub operation: &'s CompiledOperation,
}

impl CompiledSpec {
    /// Find the operation for `method` and `path`. `path` is the request
    /// path as sent, percent-encoded and without the query string; each
    /// segment is decoded before matching.
    pub fn match_operation(&self, method: &str, path: &str) -> Match<'_> {
        let decoded = decode_path(path);
        let Some(route) = self.match_route(&decoded) else {
            return Match::Unmatched(Unmatched::Path);
        };
        match route.check_method(method) {
            Ok(operation) => Match::Operation(MatchedOperation {
                spec: self,
                template: route.template,
                path_params: route
                    .params
                    .iter()
                    .map(|(name, value)| (*name, value.to_string()))
                    .collect(),
                operation,
            }),
            Err(unmatched) => Match::Unmatched(unmatched),
        }
    }

    /// Check the `Content-Type` and the body against `operation`'s request
    /// body, if it declares one. `body` is `None` when the request has none.
    pub fn validate_body(
        &self,
        operation: &CompiledOperation,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();
        let Some(req_body) = &operation.request_body else {
            return violations;
        };

        // A request that carries no body has nothing for Content-Type to
        // describe, so the header is only demanded when a body is present or
        // required.
        let has_body = body.is_some_and(|b| !b.is_empty());
        if has_body || req_body.required {
            let expected: Vec<&mime::Mime> = req_body.media_types().collect();
            content_type::validate_content_type(content_type, &expected, &mut violations);
        }

        let request_media_type = content_type.and_then(content_type::parse_media_type);
        // The declared media type that accepts the request's Content-Type.
        let media = request_media_type
            .as_ref()
            .and_then(|ct| req_body.find_media_type(ct));
        // Without a Content-Type, JSON is assumed since that is what the
        // schema describes.
        let kind = request_media_type
            .as_ref()
            .map_or(body::BodyKind::Json, content_type::body_kind);
        body::validate_body(
            body,
            req_body.required,
            media,
            kind,
            self.document(),
            &mut violations,
        );
        violations
    }
}

/// Percent-decode each path segment on its own, so an encoded `/` (`%2F`)
/// does not become a segment separator. Invalid escapes are kept as written.
fn decode_path(path: &str) -> String {
    if !path.contains('%') {
        return path.to_string();
    }
    let mut out = Vec::with_capacity(path.len());
    for (i, segment) in path.split('/').enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        let bytes = segment.as_bytes();
        let mut j = 0;
        while j < bytes.len() {
            let escape = (bytes[j] == b'%')
                .then(|| bytes.get(j + 1..j + 3))
                .flatten()
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            match escape {
                Some(b'/') => out.extend_from_slice(b"%2F"),
                Some(byte) => out.push(byte),
                None => {
                    out.push(bytes[j]);
                    j += 1;
                    continue;
                }
            }
            j += 3;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl MatchedOperation<'_> {
    /// Check the path, query, header and cookie parameters. Header names are
    /// matched case-insensitively; cookies are read from `Cookie` headers.
    pub fn validate_parameters(
        &self,
        query: Option<&str>,
        headers: &[(String, String)],
    ) -> Vec<Violation> {
        let root = self.spec.document();
        let op = self.operation;
        let mut violations = Vec::new();

        let captured: Vec<(&str, &str)> = self
            .path_params
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        params::validate_path_params(&captured, &op.path_params, root, &mut violations);

        let query_pairs = query.map(params::parse_query_string).unwrap_or_default();
        params::validate_query_params(&query_pairs, &op.query_params, root, &mut violations);

        params::validate_header_params(headers, &op.header_params, root, &mut violations);

        let cookie_pairs = extract_cookies(headers);
        params::validate_cookie_params(&cookie_pairs, &op.cookie_params, root, &mut violations);

        violations
    }

    /// Query parameter names in `query` that the operation does not declare.
    pub fn undeclared_query_parameters(&self, query: &str) -> Vec<String> {
        let root = self.spec.document();
        let mut seen = std::collections::HashSet::new();
        params::parse_query_string(query)
            .into_iter()
            .map(|(key, _)| key)
            .filter(|key| {
                !self
                    .operation
                    .query_params
                    .iter()
                    .any(|p| params::query_key_belongs_to(key, p, root))
            })
            .filter(|key| seen.insert(key.clone()))
            .collect()
    }

    /// Check the `Content-Type` and the body; see [`CompiledSpec::validate_body`].
    #[cfg(test)]
    pub fn validate_body(&self, content_type: Option<&str>, body: Option<&[u8]>) -> Vec<Violation> {
        self.spec.validate_body(self.operation, content_type, body)
    }
}

/// A whole request, for validating in one step.
#[cfg(test)]
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
}

#[cfg(test)]
pub fn validate_request(spec: &CompiledSpec, request: &Request<'_>) -> ValidationResult {
    let operation = match spec.match_operation(request.method, request.path) {
        Match::Operation(operation) => operation,
        Match::Unmatched(unmatched) => return ValidationResult::Unmatched(unmatched),
    };
    let content_type = header(request.headers, "content-type");
    let mut violations = operation.validate_parameters(request.query, request.headers);
    violations.extend(operation.validate_body(content_type, request.body));
    if violations.is_empty() {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid(violations)
    }
}

#[cfg(test)]
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Extract cookies from the Cookie headers into name-value pairs, parsed
/// the same way as the `http.request.cookies` field.
fn extract_cookies(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| cookie::Cookie::split_parse(v).filter_map(Result::ok))
        .map(|c| (c.name().to_string(), c.value().to_string()))
        .collect()
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    const SPEC: &str = r#"{
  "openapi": "3.1.0",
  "info": { "title": "Test API", "version": "1.0" },
  "paths": {
    "/users": {
      "get": {
        "parameters": [
          { "name": "page", "in": "query", "required": true, "schema": { "type": "integer" } },
          { "name": "limit", "in": "query", "schema": { "type": "integer" } }
        ],
        "responses": { "200": { "description": "OK" } }
      },
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                  "name": { "type": "string" },
                  "email": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": { "201": { "description": "Created" } }
      }
    },
    "/users/{id}": {
      "get": {
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }
        ],
        "responses": { "200": { "description": "OK" } }
      }
    }
  }
}"#;

    fn spec() -> CompiledSpec {
        CompiledSpec::from_json(SPEC).unwrap()
    }

    fn get(path: &str, query: Option<&str>) -> ValidationResult {
        validate_request(
            &spec(),
            &Request {
                method: "GET",
                path,
                query,
                headers: &[],
                body: None,
            },
        )
    }

    fn post(content_type: &str, body: Option<&[u8]>) -> ValidationResult {
        let headers = [("Content-Type".to_string(), content_type.to_string())];
        validate_request(
            &spec(),
            &Request {
                method: "POST",
                path: "/users",
                query: None,
                headers: &headers,
                body,
            },
        )
    }

    fn violations(result: ValidationResult) -> Vec<Violation> {
        match result {
            ValidationResult::Invalid(v) => v,
            other => panic!("expected violations, got {other:?}"),
        }
    }

    #[test]
    fn valid_get_request() {
        assert!(get("/users", Some("page=1&limit=10")).is_valid());
        assert!(get("/users/42", None).is_valid());
    }

    #[test]
    fn unmatched_path_and_method() {
        let result = get("/nonexistent", None);
        assert!(matches!(
            result,
            ValidationResult::Unmatched(Unmatched::Path)
        ));
        assert_eq!(result.http_status(), Some(404));

        let result = validate_request(
            &spec(),
            &Request {
                method: "DELETE",
                path: "/users",
                query: None,
                headers: &[],
                body: None,
            },
        );
        assert!(matches!(
            &result,
            ValidationResult::Unmatched(Unmatched::Method { allowed }) if allowed == &["GET", "POST"]
        ));
        assert_eq!(result.http_status(), Some(405));
    }

    #[test]
    fn missing_required_query_param() {
        let result = get("/users", Some("limit=10"));
        assert_eq!(result.http_status(), Some(400));
        let v = violations(result);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].location, Location::Query);
        assert_eq!(v[0].class, ErrorClass::MissingRequired);
        assert_eq!(v[0].target, "page");
    }

    #[test]
    fn wrongly_typed_query_param() {
        let v = violations(get("/users", Some("page=abc")));
        assert_eq!(v[0].location, Location::Query);
        assert_eq!(v[0].class, ErrorClass::InvalidType);
        assert_eq!(v[0].target, "page");
        assert!(
            v[0].message.contains("query parameter 'page'"),
            "{}",
            v[0].message
        );
    }

    #[test]
    fn body_validation() {
        assert!(post("application/json", Some(br#"{"name": "Alice"}"#)).is_valid());

        let v = violations(post("application/json", None));
        assert_eq!(
            (v[0].location, v[0].class),
            (Location::Body, ErrorClass::MissingRequired)
        );
        assert_eq!(v[0].target, "");

        let v = violations(post(
            "application/json",
            Some(br#"{"email": "a@example.com"}"#),
        ));
        assert_eq!(
            (v[0].location, v[0].class),
            (Location::Body, ErrorClass::MissingRequired)
        );
        assert_eq!(v[0].target, "/name");

        // The media type is matched case-insensitively, so the schema applies.
        assert_eq!(
            post(
                "Application/JSON; charset=utf-8",
                Some(br#"{"email": "a@example.com"}"#)
            )
            .http_status(),
            Some(400)
        );

        let result = post("text/plain", Some(b"not json"));
        assert_eq!(result.http_status(), Some(415));
        let v = violations(result);
        assert_eq!(
            (v[0].location, v[0].class),
            (Location::Header, ErrorClass::UnsupportedMediaType)
        );
        assert_eq!(v[0].target, "content-type");
    }

    #[test]
    fn parameters_and_body_validate_separately() {
        let spec = spec();
        let Match::Operation(op) = spec.match_operation("POST", "/users") else {
            panic!("expected a match");
        };
        assert_eq!(op.template, "/users");
        assert!(op.validate_parameters(None, &[]).is_empty());
        let v = op.validate_body(Some("application/json"), Some(b"{}"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].target, "/name");

        let Match::Operation(op) = spec.match_operation("GET", "/users/7") else {
            panic!("expected a match");
        };
        assert_eq!(op.path_params, [("id", "7".to_string())]);
        assert!(
            op.validate_body(None, None).is_empty(),
            "GET declares no body"
        );
        assert_eq!(op.undeclared_query_parameters("id=1&x=2&x=3"), ["id", "x"]);
    }

    #[test]
    fn string_query_param_accepts_numeric_value() {
        let spec = CompiledSpec::from_json(
            r#"{"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {"/q": {"get": {
            "parameters": [{"name": "name", "in": "query", "required": true, "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}}}}}"#,
        )
        .unwrap();
        let result = validate_request(
            &spec,
            &Request {
                method: "GET",
                path: "/q",
                query: Some("name=123"),
                headers: &[],
                body: None,
            },
        );
        assert!(result.is_valid());
    }

    #[test]
    fn form_body_is_not_parsed_as_json() {
        let spec = CompiledSpec::from_json(
            r#"{"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {"/f": {"post": {
            "requestBody": {"required": true, "content": {"application/x-www-form-urlencoded": {"schema": {"type": "object"}}}},
            "responses": {"200": {"description": "ok"}}}}}}"#,
        )
        .unwrap();
        let headers = [(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )];
        let result = validate_request(
            &spec,
            &Request {
                method: "POST",
                path: "/f",
                query: None,
                headers: &headers,
                body: Some(b"a=1&b=2"),
            },
        );
        assert!(result.is_valid());
    }

    #[test]
    fn cookies_are_parsed_from_the_header() {
        let headers = [
            ("Cookie".to_string(), "a=1; b=x=y; c".to_string()),
            ("cookie".to_string(), "d=\"quoted\"; =nameless".to_string()),
        ];
        assert_eq!(
            extract_cookies(&headers),
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "x=y".to_string()),
                ("d".to_string(), "\"quoted\"".to_string()),
            ]
        );
    }

    #[test]
    fn path_segments_are_decoded_individually() {
        assert_eq!(decode_path("/a%20b/%34%32"), "/a b/42");
        assert_eq!(decode_path("/pets/4%2F2/x"), "/pets/4%2F2/x");
        assert_eq!(decode_path("/a%2fb"), "/a%2Fb");
        assert_eq!(decode_path("/a%zz/%4"), "/a%zz/%4");
        assert_eq!(decode_path("/plain"), "/plain");

        let spec = spec();
        let Match::Operation(op) = spec.match_operation("GET", "/users/%34%32") else {
            panic!("expected a match");
        };
        assert_eq!(op.path_params, [("id", "42".to_string())]);
        assert!(op.validate_parameters(None, &[]).is_empty());

        // An encoded slash stays inside the segment and is not an integer.
        let Match::Operation(op) = spec.match_operation("GET", "/users/4%2F2") else {
            panic!("expected a match");
        };
        assert_eq!(op.path_params, [("id", "4%2F2".to_string())]);
        assert_eq!(op.validate_parameters(None, &[]).len(), 1);
        assert!(matches!(
            spec.match_operation("GET", "/users%2F42"),
            Match::Unmatched(Unmatched::Path)
        ));
    }

    #[test]
    fn undeclared_query_parameters_are_unique() {
        let spec = spec();
        let Match::Operation(op) = spec.match_operation("GET", "/users") else {
            panic!("expected a match");
        };
        assert_eq!(
            op.undeclared_query_parameters("x=1&y=2&x=3&page=1"),
            ["x", "y"]
        );
    }
}
