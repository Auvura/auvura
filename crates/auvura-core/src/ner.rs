//! NER (Named Entity Recognition) support for unstructured PII detection.
//!
//! Re-exports NER-related types from the detectors module.

pub use crate::detectors::ner::{NerDetector, SimpleNameDetector, TokenRedactor};
