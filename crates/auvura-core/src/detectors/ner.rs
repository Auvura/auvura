//! NER-based detector for unstructured PII (names, organizations)
//!
//! Uses BERT models via candle for Named Entity Recognition
//! to detect people, organizations, and locations in text.

#[cfg(feature = "ner")]
use candle_core;
#[cfg(feature = "ner")]
use candle_transformers;

use crate::{detector::{Detection, PiiDetector}, types::PiiType};
use std::collections::HashMap;

/// NER-based detector for unstructured PII
#[cfg(feature = "ner")]
pub struct NerDetector {
    model_path: String,
    tokenizer_path: String,
}

#[cfg(feature = "ner")]
impl NerDetector {
    pub fn new(model_path: &str, tokenizer_path: &str) -> Self {
        Self {
            model_path: model_path.to_string(),
            tokenizer_path: tokenizer_path.to_string(),
        }
    }

    fn load_model(&self) -> Result<NERModel, String> {
        // Placeholder for actual candle model loading
        // In production, this would load BERT from the specified paths
        Err("NER feature not yet fully implemented".to_string())
    }
}

#[cfg(feature = "ner")]
impl PiiDetector for NerDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::Other("PERSON".to_string())
    }

    fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
        // Placeholder: In production, run BERT NER inference here
        // For now, return empty vec
        let _ = text;
        vec![]
    }
}

/// Placeholder for when NER feature is disabled
#[cfg(not(feature = "ner"))]
pub struct NerDetector;

#[cfg(not(feature = "ner"))]
impl NerDetector {
    pub fn new(_model_path: &str, _tokenizer_path: &str) -> Self {
        Self
    }
}

/// Non-BERT based fallback for names (simple heuristic)
/// Used when NER feature is disabled
pub struct SimpleNameDetector;

impl SimpleNameDetector {
    pub fn new() -> Self {
        Self
    }
}

impl PiiDetector for SimpleNameDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::Other("PERSON".to_string())
    }

    fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Simple heuristic: capitalized words that might be names
        // This is a basic fallback - real NER uses BERT
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut byte_offset = 0;

        for word in words {
            let trimmed = word.trim_matches(|c: char| !c.is_alphabetic());
            if !trimmed.is_empty()
                && trimmed.chars().next().map_or(false, |c| c.is_uppercase())
                && trimmed.len() > 1
                && trimmed.chars().all(|c| c.is_alphabetic())
            {
                // Check if it's not at the start of a sentence
                if let Some(start) = text[byte_offset..].find(trimmed) {
                    let abs_start = byte_offset + start;
                    detections.push(Detection {
                        pii_type: self.pii_type(),
                        start: abs_start,
                        end: abs_start + trimmed.len(),
                        original: trimmed.to_string(),
                    });
                }
            }
            byte_offset += word.len() + 1; // +1 for space
        }

        detections
    }
}

/// Token-based redaction for NER detections
pub struct TokenRedactor {
    token_map: HashMap<String, String>,
    counter: std::sync::atomic::AtomicUsize,
}

impl TokenRedactor {
    pub fn new() -> Self {
        Self {
            token_map: HashMap::new(),
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Replace PII with unique tokens (e.g., [[PERSON_1]])
    pub fn redact_with_tokens(&mut self, text: &str, detections: &[Detection]) -> String {
        let mut result = text.to_string();

        // Sort by start position in reverse order to maintain correct offsets
        let mut sorted = detections.to_vec();
        sorted.sort_by(|a, b| b.start.cmp(&a.start));

        for detection in sorted {
            let token = self.get_or_create_token(&detection.original, &detection.pii_type);
            result.replace_range(detection.start..detection.end, &token);
        }

        result
    }

    fn get_or_create_token(&mut self, original: &str, pii_type: &PiiType) -> String {
        if let Some(token) = self.token_map.get(original) {
            return token.clone();
        }

        let counter = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let token = match pii_type {
            PiiType::Email => format!("[[EMAIL_{}]]", counter),
            PiiType::PhoneNumber => format!("[[PHONE_{}]]", counter),
            PiiType::Ssn => format!("[[SSN_{}]]", counter),
            PiiType::CreditCard => format!("[[CC_{}]]", counter),
            PiiType::Other(name) => format!("[[{}_{}]]", name.to_uppercase(), counter),
            _ => format!("[[PII_{}]]", counter),
        };

        self.token_map.insert(original.to_string(), token.clone());
        token
    }
}

/// Placeholder PII type for NER-detected entities
impl PiiType {
    pub fn other(label: String) -> Self {
        PiiType::Other(label)
    }
}
