//! NER-based detector for unstructured PII (names, organizations)
//!
//! Uses heuristic-based detection for people names in text.
//! BERT-based NER via candle is planned for a future release.

use crate::{
    detector::{Detection, PiiDetector},
    types::PiiType,
};
use std::collections::HashMap;

/// NER-based detector for unstructured PII
///
/// Currently a placeholder for future BERT-based NER.
/// Returns empty results — use `SimpleNameDetector` for heuristic fallback.
#[allow(dead_code)]
pub struct NerDetector {
    model_path: String,
    tokenizer_path: String,
}

impl NerDetector {
    pub fn new(model_path: &str, tokenizer_path: &str) -> Self {
        Self {
            model_path: model_path.to_string(),
            tokenizer_path: tokenizer_path.to_string(),
        }
    }
}

impl PiiDetector for NerDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::Other("PERSON")
    }

    fn detect(&self, _text: &str) -> Vec<Detection> {
        // Placeholder: BERT NER inference not yet implemented
        vec![]
    }
}

/// Heuristic-based fallback for name detection
///
/// Detects capitalized words that are not at sentence start.
/// Higher false-positive rate than BERT NER — use as fallback only.
pub struct SimpleNameDetector;

impl SimpleNameDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SimpleNameDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiDetector for SimpleNameDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::Other("PERSON")
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        let words: Vec<&str> = text.split_whitespace().collect();
        let mut byte_offset = 0;

        for word in words {
            let trimmed = word.trim_matches(|c: char| !c.is_alphabetic());
            if !trimmed.is_empty()
                && trimmed.chars().next().is_some_and(|c| c.is_uppercase())
                && trimmed.len() > 1
                && trimmed.chars().all(|c| c.is_alphabetic())
            {
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
            byte_offset += word.len() + 1;
        }

        detections
    }
}

/// Token-based redaction for NER detections
///
/// Replaces PII with unique tokens like `[[PERSON_1]]`, `[[EMAIL_2]]`.
/// Maintains a mapping from original text to tokens for reconstruction.
pub struct TokenRedactor {
    token_map: HashMap<String, String>,
    counter: std::sync::atomic::AtomicUsize,
}

impl Default for TokenRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenRedactor {
    pub fn new() -> Self {
        Self {
            token_map: HashMap::new(),
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Replace PII with unique tokens (e.g., `[[PERSON_1]]`)
    pub fn redact_with_tokens(&mut self, text: &str, detections: &[Detection]) -> String {
        let mut result = text.to_string();

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
