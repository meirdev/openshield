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
pub enum Match<'s, 'p> {
    Operation(MatchedOperation<'s, 'p>),
    Unmatched(Unmatched),
}

/// An operation matched to a request path, ready to validate the request.
pub struct MatchedOperation<'s, 'p> {
    spec: &'s CompiledSpec,
    /// The OpenAPI path template that matched.
    pub template: &'s str,
    /// Path parameters captured from the request path, in template order.
    pub path_params: Vec<(&'s str, &'p str)>,
    pub operation: &'s CompiledOperation,
}

impl CompiledSpec {
    /// Find the operation for `method` and `path`. `path` is percent-decoded
    /// and carries no query string.
    pub fn match_operation<'s, 'p>(&'s self, method: &str, path: &'p str) -> Match<'s, 'p> {
        let Some(route) = self.match_route(path) else {
            return Match::Unmatched(Unmatched::Path);
        };
        match route.check_method(method) {
            Ok(operation) => Match::Operation(MatchedOperation {
                spec: self,
                template: route.template,
                path_params: route.params,
                operation,
            }),
            Err(unmatched) => Match::Unmatched(unmatched),
        }
    }
}

impl MatchedOperation<'_, '_> {
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

        params::validate_path_params(&self.path_params, &op.path_params, root, &mut violations);

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
        let mut names: Vec<String> = params::parse_query_string(query)
            .into_iter()
            .map(|(key, _)| key)
            .filter(|key| {
                !self
                    .operation
                    .query_params
                    .iter()
                    .any(|p| params::query_key_belongs_to(key, p, root))
            })
            .collect();
        names.dedup();
        names
    }

    /// Check the `Content-Type` and the body against the operation's request
    /// body, if it declares one. `body` is `None` when the request has none.
    pub fn validate_body(&self, content_type: Option<&str>, body: Option<&[u8]>) -> Vec<Violation> {
        let mut violations = Vec::new();
        let Some(req_body) = &self.operation.request_body else {
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
            self.spec.document(),
            &mut violations,
        );
        violations
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

/// Extract cookies from the Cookie header into key-value pairs.
fn extract_cookies(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| {
            v.split(';').map(|cookie| {
                let (name, value) = cookie.trim().split_once('=').unwrap_or((cookie.trim(), ""));
                (name.to_string(), value.to_string())
            })
        })
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
        assert_eq!(op.path_params, [("id", "7")]);
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
        let headers = [("Cookie".to_string(), "a=1; b=x=y; c".to_string())];
        assert_eq!(
            extract_cookies(&headers),
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "x=y".to_string()),
                ("c".to_string(), String::new()),
            ]
        );
    }
}
