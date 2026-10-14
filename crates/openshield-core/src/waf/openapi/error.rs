use serde::Serialize;

/// The part of the request a violation was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

impl Location {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Body => "body",
        }
    }
}

/// A stable, coarse category of violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    MissingRequired,
    InvalidType,
    InvalidEncoding,
    InvalidSyntax,
    InvalidMediaType,
    UnsupportedMediaType,
    DuplicateValue,
    ConstraintViolation,
    BodySize,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingRequired => "missing_required",
            Self::InvalidType => "invalid_type",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidSyntax => "invalid_syntax",
            Self::InvalidMediaType => "invalid_media_type",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::DuplicateValue => "duplicate_value",
            Self::ConstraintViolation => "constraint_violation",
            Self::BodySize => "body_size",
        }
    }
}

/// One way in which a request does not conform to its operation.
#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub location: Location,
    pub class: ErrorClass,
    /// What exactly was violated, beyond the class: `expected:string`,
    /// `pattern_no_match`, `format_violation:uuid`, ...
    pub detail: Option<String>,
    /// The parameter, header or cookie name, or the JSON pointer within the
    /// body (`""` for the whole body).
    pub target: String,
    pub message: String,
}

impl Violation {
    pub fn new(
        location: Location,
        class: ErrorClass,
        detail: Option<&str>,
        target: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            location,
            class,
            detail: detail.map(str::to_string),
            target: target.into(),
            message: message.into(),
        }
    }

    /// A violation reported by the JSON Schema engine for the value at
    /// `target`; `location` says which part of the request held it.
    pub(crate) fn schema(
        location: Location,
        target: &str,
        error: &jsonschema::ValidationError<'_>,
    ) -> Self {
        use jsonschema::error::{TypeKind, ValidationErrorKind as K};

        let mut target = target.to_string();
        let (class, detail) = match error.kind() {
            K::Type { kind } => {
                let expected = match kind {
                    TypeKind::Single(t) => format!("{t:?}"),
                    TypeKind::Multiple(set) => format!("{set:?}"),
                };
                (
                    ErrorClass::InvalidType,
                    Some(format!("expected:{}", expected.to_lowercase())),
                )
            }
            K::Required { property } => {
                if let Some(name) = property.as_str() {
                    target = format!("{target}/{}", name.replace('~', "~0").replace('/', "~1"));
                }
                (ErrorClass::MissingRequired, None)
            }
            K::UniqueItems => (ErrorClass::DuplicateValue, Some("unique_items".into())),
            K::ContentEncoding { content_encoding } => (
                ErrorClass::InvalidEncoding,
                Some(format!("content_encoding:{content_encoding}")),
            ),
            other => (
                ErrorClass::ConstraintViolation,
                Some(constraint_name(other)),
            ),
        };
        Self {
            location,
            class,
            detail,
            target,
            message: error.to_string(),
        }
    }

    #[cfg(test)]
    pub fn http_status(&self) -> u16 {
        match self.class {
            ErrorClass::InvalidMediaType | ErrorClass::UnsupportedMediaType => 415,
            ErrorClass::BodySize => 413,
            _ => 400,
        }
    }
}

/// The keyword a `constraint_violation` comes from, in snake case.
fn constraint_name(kind: &jsonschema::error::ValidationErrorKind) -> String {
    use jsonschema::error::ValidationErrorKind as K;
    match kind {
        K::Format { format } => format!("format_violation:{format}"),
        K::Pattern { .. } => "pattern_no_match".into(),
        K::Enum { .. } => "enum".into(),
        K::Constant { .. } => "const".into(),
        K::Minimum { .. } => "minimum".into(),
        K::Maximum { .. } => "maximum".into(),
        K::ExclusiveMinimum { .. } => "exclusive_minimum".into(),
        K::ExclusiveMaximum { .. } => "exclusive_maximum".into(),
        K::MultipleOf { .. } => "multiple_of".into(),
        K::MinLength { .. } => "min_length".into(),
        K::MaxLength { .. } => "max_length".into(),
        K::MinItems { .. } => "min_items".into(),
        K::MaxItems { .. } => "max_items".into(),
        K::MinProperties { .. } => "min_properties".into(),
        K::MaxProperties { .. } => "max_properties".into(),
        K::AdditionalProperties { .. } | K::UnevaluatedProperties { .. } => {
            "additional_properties".into()
        }
        K::AdditionalItems { .. } | K::UnevaluatedItems { .. } => "additional_items".into(),
        K::AnyOf { .. } => "any_of".into(),
        K::OneOfNotValid { .. } | K::OneOfMultipleValid { .. } => "one_of".into(),
        K::Not { .. } => "not".into(),
        K::Contains => "contains".into(),
        K::PropertyNames { .. } => "property_names".into(),
        K::FalseSchema => "false_schema".into(),
        K::ContentMediaType { .. } => "content_media_type".into(),
        K::Custom { keyword, .. } => keyword.clone(),
        _ => "schema".into(),
    }
}

/// Why no operation matched the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unmatched {
    /// No path template matches the request path.
    Path,
    /// The path matches but declares no operation for this method.
    Method { allowed: Vec<String> },
}

impl Unmatched {
    #[cfg(test)]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Path => 404,
            Self::Method { .. } => 405,
        }
    }
}

/// The outcome of validating a whole request; see `validate_request`.
#[cfg(test)]
#[derive(Debug)]
pub enum ValidationResult {
    Valid,
    Unmatched(Unmatched),
    Invalid(Vec<Violation>),
}

#[cfg(test)]
impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// The most appropriate HTTP status code for the outcome, if it is not
    /// valid. Among violations, the most specific status wins regardless of
    /// order: 415, then 413, then 400.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Valid => None,
            Self::Unmatched(unmatched) => Some(unmatched.http_status()),
            Self::Invalid(violations) => {
                violations
                    .iter()
                    .map(Violation::http_status)
                    .max_by_key(|status| match status {
                        415 => 2,
                        413 => 1,
                        _ => 0,
                    })
            }
        }
    }
}

#[derive(Debug)]
pub enum SpecError {
    Parse(String),
    PathTemplate(String, String),
    RefResolution(String),
    SchemaCompile(String),
}

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "failed to parse OpenAPI spec: {e}"),
            Self::PathTemplate(template, e) => {
                write!(f, "invalid path template '{template}': {e}")
            }
            Self::RefResolution(e) => write!(f, "failed to resolve reference: {e}"),
            Self::SchemaCompile(e) => write!(f, "failed to compile JSON schema: {e}"),
        }
    }
}

impl std::error::Error for SpecError {}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn violation(class: ErrorClass) -> Violation {
        Violation::new(Location::Body, class, None, "", "")
    }

    #[test]
    fn most_specific_status_wins() {
        let r = ValidationResult::Invalid(vec![
            violation(ErrorClass::InvalidType),
            violation(ErrorClass::UnsupportedMediaType),
        ]);
        assert_eq!(r.http_status(), Some(415));
        let r = ValidationResult::Invalid(vec![
            violation(ErrorClass::BodySize),
            violation(ErrorClass::InvalidType),
        ]);
        assert_eq!(r.http_status(), Some(413));
        assert_eq!(
            ValidationResult::Unmatched(Unmatched::Path).http_status(),
            Some(404)
        );
        assert_eq!(ValidationResult::Valid.http_status(), None);
    }

    /// Violations the schema engine reports for `instance` against `schema`.
    fn schema_violations(schema: serde_json::Value, instance: serde_json::Value) -> Vec<Violation> {
        let validator = jsonschema::validator_for(&schema).unwrap();
        validator
            .iter_errors(&instance)
            .map(|e| Violation::schema(Location::Body, &e.instance_path().to_string(), &e))
            .collect()
    }

    #[test]
    fn schema_errors_map_to_classes() {
        let schema = json!({
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": {"type": "integer", "minimum": 1},
                "tag": {"type": "string", "pattern": "^[a-z]+$", "format": "email"},
                "list": {"type": "array", "uniqueItems": true}
            },
            "additionalProperties": false
        });
        let instance = json!({
            "tag": "A", "list": [1, 1], "extra": true
        });
        let v = schema_violations(schema.clone(), instance);
        let find = |target: &str, class: ErrorClass| {
            v.iter()
                .find(|v| v.target == target && v.class == class)
                .unwrap_or_else(|| panic!("no {class:?} at '{target}' in {v:#?}"))
        };
        assert_eq!(find("/id", ErrorClass::MissingRequired).detail, None);
        assert_eq!(
            find("/tag", ErrorClass::ConstraintViolation)
                .detail
                .as_deref(),
            Some("pattern_no_match")
        );
        assert_eq!(
            find("/list", ErrorClass::DuplicateValue).detail.as_deref(),
            Some("unique_items")
        );
        assert_eq!(
            find("", ErrorClass::ConstraintViolation).detail.as_deref(),
            Some("additional_properties")
        );

        let v = schema_violations(schema, json!({"id": "x"}));
        assert_eq!(v[0].class, ErrorClass::InvalidType);
        assert_eq!(v[0].target, "/id");
        assert_eq!(v[0].detail.as_deref(), Some("expected:integer"));
    }
}
