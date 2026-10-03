use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    pub kind: ValidationErrorKind,
    pub message: String,
    /// JSON pointer or parameter name indicating where the error occurred.
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationErrorKind {
    PathNotFound,
    MethodNotAllowed,
    MissingRequiredParam,
    InvalidParamValue,
    UnsupportedContentType,
    MissingRequiredBody,
    InvalidBody,
    SchemaValidation,
}

impl ValidationErrorKind {
    /// Maps validation error kind to an HTTP status code.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::PathNotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::UnsupportedContentType => 415,
            _ => 400,
        }
    }
}

#[derive(Debug)]
pub enum ValidationResult {
    Valid,
    Invalid(Vec<ValidationError>),
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns the most appropriate HTTP status code for the validation errors.
    ///
    /// The most specific status wins regardless of error order: 404, then
    /// 405, then 415, then 400. A request with a bad query parameter and an
    /// unsupported Content-Type is therefore reported as 415.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Valid => None,
            Self::Invalid(errors) => {
                errors
                    .iter()
                    .map(|e| e.kind.http_status())
                    .max_by_key(|status| match status {
                        404 => 3,
                        405 => 2,
                        415 => 1,
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
    use super::*;

    fn err(kind: ValidationErrorKind) -> ValidationError {
        ValidationError {
            kind,
            message: String::new(),
            path: String::new(),
        }
    }

    #[test]
    fn most_specific_status_wins() {
        let r = ValidationResult::Invalid(vec![
            err(ValidationErrorKind::InvalidParamValue),
            err(ValidationErrorKind::UnsupportedContentType),
        ]);
        assert_eq!(r.http_status(), Some(415));
        let r = ValidationResult::Invalid(vec![err(ValidationErrorKind::SchemaValidation)]);
        assert_eq!(r.http_status(), Some(400));
        assert_eq!(ValidationResult::Valid.http_status(), None);
    }
}
