//! OpenShield WAF engine.
//!
//! Server-agnostic core: configuration, rule compilation, per-phase
//! evaluation, and the request/response validators. Host integrations
//! (such as `openshield-pingora`) feed it request data and act on its
//! verdicts.

pub mod challenge;
pub mod compiler;
pub mod config;
pub mod geoip;
pub mod logging;
pub mod waf;
