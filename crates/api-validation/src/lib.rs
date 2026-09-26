//! Pure, bounded OpenAPI response-contract validation.
//!
//! This crate performs no network or filesystem I/O. Callers acquire OpenAPI
//! documents and response bodies through centrally authorized typed actions,
//! seal their receipts, and submit only receipt lineage plus value-free JSON
//! shapes here.

mod contract;
mod openapi;
mod shape;
mod validate;

pub use contract::*;
pub use openapi::{normalize_openapi, OpenApiDocumentInput};
pub use shape::{JsonShape, JsonShapeCapture};
pub use validate::{classify_response, compare_replay, violation_hash, ApiValidationSession};
