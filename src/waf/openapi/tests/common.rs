#![allow(dead_code)]

use serde_json::{Value, json};

use crate::waf::openapi::error::{ErrorClass, Location, ValidationResult, Violation};
use crate::waf::openapi::{CompiledSpec, Request, validate_request};

pub fn document(version: &str, media_type: &str, media: Value, schemas: Value) -> Value {
    json!({
        "openapi": version,
        "info": {"title": "libopenapi-validator parity", "version": "1.0.0"},
        "paths": {"/test": {"post": {
            "requestBody": {"required": true, "content": {media_type: media}},
            "responses": {"200": {"description": "OK"}}
        }}},
        "components": {"schemas": schemas}
    })
}

pub fn compile(version: &str, schema: Value, schemas: Value) -> CompiledSpec {
    compile_media(
        version,
        "application/json",
        json!({"schema": schema}),
        schemas,
    )
}

pub fn compile_media(
    version: &str,
    media_type: &str,
    media: Value,
    schemas: Value,
) -> CompiledSpec {
    let doc = document(version, media_type, media, schemas);
    CompiledSpec::from_json(&doc.to_string())
        .unwrap_or_else(|error| panic!("reference schema must compile: {error}\n{doc}"))
}

pub fn validate_raw(spec: &CompiledSpec, media_type: &str, body: &str) -> ValidationResult {
    let headers = [("Content-Type".to_string(), media_type.to_string())];
    validate_request(
        spec,
        &Request {
            method: "POST",
            path: "/test",
            query: None,
            headers: &headers,
            body: Some(body.as_bytes()),
        },
    )
}

pub fn validate(spec: &CompiledSpec, body: Value) -> ValidationResult {
    validate_raw(spec, "application/json", &body.to_string())
}

/// Classes the JSON Schema engine reports, as opposed to decoding failures.
pub fn is_schema_class(class: ErrorClass) -> bool {
    matches!(
        class,
        ErrorClass::InvalidType
            | ErrorClass::ConstraintViolation
            | ErrorClass::MissingRequired
            | ErrorClass::DuplicateValue
    )
}

#[track_caller]
pub fn assert_valid(result: ValidationResult) {
    assert!(
        result.is_valid(),
        "expected a valid request, got {result:#?}"
    );
    assert_eq!(result.http_status(), None);
}

/// Every violation is in the body and satisfies `class_ok`.
#[track_caller]
fn assert_body_violations(
    result: ValidationResult,
    class_ok: impl Fn(ErrorClass) -> bool,
) -> Vec<Violation> {
    assert_eq!(result.http_status(), Some(400), "{result:#?}");
    match result {
        ValidationResult::Invalid(violations) => {
            assert!(
                !violations.is_empty(),
                "invalid results must explain the failure"
            );
            for v in &violations {
                assert_eq!(v.location, Location::Body, "{v:#?}");
                assert!(class_ok(v.class), "{v:#?}");
                assert!(!v.message.is_empty(), "{v:#?}");
            }
            violations
        }
        other => panic!("expected rejection, got {other:#?}"),
    }
}

/// Rejected for any reason found in the body.
#[track_caller]
pub fn assert_rejected(result: ValidationResult) -> Vec<Violation> {
    assert_body_violations(result, |_| true)
}

#[track_caller]
pub fn assert_invalid(result: ValidationResult, class: ErrorClass) -> Vec<Violation> {
    assert_body_violations(result, |c| c == class)
}

#[track_caller]
pub fn assert_schema_invalid(result: ValidationResult) -> Vec<Violation> {
    assert_body_violations(result, is_schema_class)
}

/// The violations' targets (JSON pointers into the body) are exactly
/// `expected`.
#[track_caller]
pub fn assert_error_paths(result: ValidationResult, expected: &[&str]) {
    let violations = assert_schema_invalid(result);
    let mut targets: Vec<_> = violations.iter().map(|v| v.target.as_str()).collect();
    targets.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(targets, expected, "{violations:#?}");
}
