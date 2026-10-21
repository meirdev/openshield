# openshield-openapi

Validates HTTP requests against an OpenAPI 3.0.x or 3.1.x document: route and method matching, path, query, header and cookie parameters, and JSON, form-urlencoded and XML bodies against their schemas.

Compile the document once with `CompiledSpec::from_yaml` or `from_json`. Per request, `match_operation` finds the operation, `validate_parameters` checks the parameters and `validate_body` checks the `Content-Type` and body. `validate_request` runs all of them.

This crate is the validator behind OpenShield's schema validation and has no dependency on the rest of OpenShield.

The test fixtures under `src/tests/fixtures` are derived from [libopenapi-validator](https://github.com/pb33f/libopenapi-validator); see `LICENSE-libopenapi-validator.md`.
