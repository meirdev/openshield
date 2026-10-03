//! Validation of HTTP requests against an OpenAPI 3.0.x or 3.1.x document.
//!
//! A [`CompiledSpec`] is built once from the document. Per request,
//! [`validate_request`] matches the path and method, decodes and checks the
//! path, query, header and cookie parameters, then checks the `Content-Type`
//! and body against the operation's request body definition.

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

pub use error::{SpecError, ValidationError, ValidationErrorKind, ValidationResult};
pub use spec::{CompiledOperation, CompiledSpec, MatchedRoute};

/// A request to validate. `path` is percent-decoded and carries no query
/// string; header names are matched case-insensitively.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
}

impl Request<'_> {
    fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
    }
}

pub fn validate_request(spec: &CompiledSpec, request: &Request<'_>) -> ValidationResult {
    let Some(matched) = spec.match_route(request.path) else {
        return ValidationResult::Invalid(vec![ValidationError {
            kind: ValidationErrorKind::PathNotFound,
            message: format!("No matching path found for '{}'", request.path),
            path: "path".to_string(),
        }]);
    };
    let operation = match matched.check_method(request.method) {
        Ok(op) => op,
        Err(err) => return ValidationResult::Invalid(vec![err]),
    };

    let root = spec.document();
    let mut errors = Vec::new();

    params::validate_path_params(&matched.params, &operation.path_params, root, &mut errors);

    let query_pairs = request
        .query
        .map(params::parse_query_string)
        .unwrap_or_default();
    params::validate_query_params(&query_pairs, &operation.query_params, root, &mut errors);

    params::validate_header_params(request.headers, &operation.header_params, root, &mut errors);

    let cookie_pairs = extract_cookies(request.headers);
    params::validate_cookie_params(&cookie_pairs, &operation.cookie_params, root, &mut errors);

    if let Some(ref req_body) = operation.request_body {
        // A request that carries no body has nothing for Content-Type to
        // describe, so the header is only demanded when a body is present or
        // required.
        let has_body = request.body.is_some_and(|b| !b.is_empty());
        if has_body || req_body.required {
            let expected: Vec<&mime::Mime> = req_body.media_types().collect();
            content_type::validate_content_type(request.content_type(), &expected, &mut errors);
        }

        let request_media_type = request
            .content_type()
            .and_then(content_type::parse_media_type);
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
            request.body,
            req_body.required,
            media,
            kind,
            root,
            &mut errors,
        );
    }

    if errors.is_empty() {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid(errors)
    }
}

/// Query parameter names in `query` that `operation` does not declare.
pub fn undeclared_query_parameters(
    spec: &CompiledSpec,
    operation: &CompiledOperation,
    query: &str,
) -> Vec<String> {
    let root = spec.document();
    let mut names: Vec<String> = params::parse_query_string(query)
        .into_iter()
        .map(|(key, _)| key)
        .filter(|key| {
            !operation
                .query_params
                .iter()
                .any(|p| params::query_key_belongs_to(key, p, root))
        })
        .collect();
    names.dedup();
    names
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

    #[test]
    fn valid_get_request() {
        assert!(get("/users", Some("page=1&limit=10")).is_valid());
        assert!(get("/users/42", None).is_valid());
    }

    #[test]
    fn unmatched_path_and_method() {
        assert_eq!(get("/nonexistent", None).http_status(), Some(404));

        let headers = [];
        let result = validate_request(
            &spec(),
            &Request {
                method: "DELETE",
                path: "/users",
                query: None,
                headers: &headers,
                body: None,
            },
        );
        assert_eq!(result.http_status(), Some(405));
    }

    #[test]
    fn missing_required_query_param() {
        let result = get("/users", Some("limit=10"));
        assert_eq!(result.http_status(), Some(400));
    }

    #[test]
    fn body_validation() {
        assert!(post("application/json", Some(br#"{"name": "Alice"}"#)).is_valid());
        assert!(
            !post("application/json", None).is_valid(),
            "body is required"
        );
        assert!(!post("application/json", Some(br#"{"email": "a@example.com"}"#)).is_valid());
        // The media type is matched case-insensitively, so the schema applies.
        assert_eq!(
            post(
                "Application/JSON; charset=utf-8",
                Some(br#"{"email": "a@example.com"}"#)
            )
            .http_status(),
            Some(400)
        );
        assert_eq!(
            post("text/plain", Some(b"not json")).http_status(),
            Some(415)
        );
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
