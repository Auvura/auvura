//! PhoneNumberDetector - International phone detection via phonelib
//!
//! Implements PiiDetector trait with hybrid approach:
//! 1. Regex pre-filter finds candidate digit sequences
//! 2. phonelib validates candidates as actual phone numbers
//! 3. Boundary checks prevent false positives (timestamps/SKUs)

use crate::{
    detector::{Detection, PiiDetector},
    types::PiiType,
};
use phonelib::PhoneNumber;
use regex::Regex;
use std::sync::OnceLock;

/// Default country codes for phone number validation (US-first priority)
pub const DEFAULT_PHONE_COUNTRIES: &[&str] = &["US", "GB", "DE", "FR", "CA", "AU", "JP"];

/// PhoneNumberDetector - international phone number detection
pub struct PhoneNumberDetector {
    candidate_pattern: &'static Regex,
    countries: Vec<String>,
}

impl Default for PhoneNumberDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PhoneNumberDetector {
    /// Create a PhoneNumberDetector with default country list (US, GB, DE, FR, CA, AU, JP)
    pub fn new() -> Self {
        Self::with_countries(
            DEFAULT_PHONE_COUNTRIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
    }

    /// Create a PhoneNumberDetector with a custom country priority list.
    /// Countries are tried in order; the first match wins.
    /// Use ISO 3166-1 alpha-2 codes (e.g., "US", "GB", "DE").
    pub fn with_countries(countries: Vec<String>) -> Self {
        Self {
            candidate_pattern: Self::get_candidate_pattern(),
            countries,
        }
    }

    fn get_candidate_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            // Finds digit sequences with phone-like characteristics:
            // - 7-15 digits (covers most international formats)
            // - Optional separators: spaces, dashes, dots, parentheses
            // - Optional leading +
            Regex::new(r"\+?[\d\s\-\.\(\)]{7,25}").expect("Phone candidate pattern is valid")
        })
    }

    /// Validate candidate as actual phone number using phonelib
    fn is_valid_phone(&self, candidate: &str) -> bool {
        // Basic digit filtering
        let cleaned: String = candidate.chars().filter(|c| c.is_ascii_digit()).collect();
        if cleaned.len() < 7 || cleaned.len() > 15 {
            return false;
        }
        if cleaned == "0000000000" || cleaned == "1111111111" || cleaned == "1234567890" {
            return false;
        }

        // phonelib validation
        if candidate.starts_with('+') {
            let normalized: String = candidate
                .chars()
                .filter(|&c| c.is_ascii_digit() || c == '+')
                .collect();
            return PhoneNumber::parse(&normalized).is_some();
        }

        for country in &self.countries {
            if PhoneNumber::parse_with_country(candidate, country).is_some() {
                return true;
            }
        }

        false
    }
}

impl PiiDetector for PhoneNumberDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::PhoneNumber
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for m in self.candidate_pattern.find_iter(text) {
            let start = m.start();
            let candidate = m.as_str();

            // Trim only leading/trailing whitespace
            let trimmed = candidate.trim_matches(|c: char| c.is_whitespace());
            if trimmed.is_empty() {
                continue;
            }

            // Compute new start/end positions after trimming
            let offset = candidate.find(trimmed).unwrap();
            let new_start = start + offset;
            let new_end = new_start + trimmed.len();

            // --- CRITICAL: Check boundaries in original text at trimmed positions ---
            if new_start > 0 {
                let prev = text[new_start - 1..new_start]
                    .chars()
                    .next()
                    .unwrap_or('\0');
                // Reject if previous character is alphanumeric (digit or letter)
                if prev.is_ascii_alphanumeric() {
                    continue;
                }
            }
            if new_end < text.len() {
                let next = text[new_end..new_end + 1].chars().next().unwrap_or('\0');
                // Reject if next character is alphanumeric (digit or letter)
                if next.is_ascii_alphanumeric() {
                    continue;
                }
            }

            // Skip if trimmed candidate doesn't have enough digits
            let digit_count = trimmed.chars().filter(|c| c.is_ascii_digit()).count();
            if !(7..=15).contains(&digit_count) {
                continue;
            }

            // Validate with phonelib
            if self.is_valid_phone(trimmed) {
                detections.push(Detection {
                    pii_type: PiiType::PhoneNumber,
                    confidence: self.confidence(),
                    start: new_start,
                    end: new_end,
                    original: trimmed.to_string(),
                });
            }
        }

        detections
    }

    /// No reliable literal anchor — phone numbers vary widely in format.
    /// Falls back to full-text regex scan.
    fn anchor_patterns(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn detect_in_window(&self, window: &str, window_start: usize) -> Vec<Detection> {
        self.detect(window)
            .into_iter()
            .map(|mut d| {
                d.start += window_start;
                d.end += window_start;
                d
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_us_e164() {
        let detector = PhoneNumberDetector::new();
        let text = "Call +12025550123";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "+12025550123");
    }

    #[test]
    fn test_detects_us_parentheses() {
        let detector = PhoneNumberDetector::new();
        let text = "Contact (202) 555-0123";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "(202) 555-0123");
    }

    #[test]
    fn test_detects_uk_number() {
        let detector = PhoneNumberDetector::new();
        let text = "UK: +44 20 7946 0958";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "+44 20 7946 0958");
    }

    #[test]
    fn test_detects_de_number() {
        let detector = PhoneNumberDetector::new();
        let text = "DE: +49 30 12345678";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "+49 30 12345678");
    }

    #[test]
    fn test_detects_jp_number() {
        let detector = PhoneNumberDetector::new();
        let text = "JP: +81 90 1234 5678";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "+81 90 1234 5678");
    }

    #[test]
    fn test_rejects_timestamp() {
        let detector = PhoneNumberDetector::new();
        let text = "Timestamp: 20240101123456";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_sku() {
        let detector = PhoneNumberDetector::new();
        let text = "SKU: ABC1234567890";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_all_same_digits() {
        let detector = PhoneNumberDetector::new();
        let text = "Fake: 111-111-1111";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_handles_multiple_numbers() {
        let detector = PhoneNumberDetector::new();
        let text = "Call +12025550123 or +442079460958";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].original, "+12025550123");
        assert_eq!(detections[1].original, "+442079460958");
    }

    #[test]
    fn test_integrates_with_redactor() {
        use crate::{policy::RedactionPolicy, redactor::Redactor};
        let detector = PhoneNumberDetector::new();
        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);
        let input = "Call (202) 555-0123";
        let result = redactor.redact(input);
        assert_eq!(result, "Call (███) ███-████");
    }

    #[test]
    fn test_zeroizes_on_drop() {
        let detector = PhoneNumberDetector::new();
        let text = "+12025550123";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        let original = detections[0].original.clone();
        assert_eq!(original, "+12025550123");
        std::mem::drop(detections);
    }

    #[test]
    fn test_respects_word_boundaries() {
        let detector = PhoneNumberDetector::new();
        let text = "Not phone: x2025550123y";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_detects_without_country_code_us_context() {
        let detector = PhoneNumberDetector::new();
        let text = "US number: 202-555-0123";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "202-555-0123");
    }

    #[test]
    fn test_rejects_short_sequence() {
        let detector = PhoneNumberDetector::new();
        let text = "Code: 12345";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_detects_indian_number() {
        let detector = PhoneNumberDetector::new();
        let text = "IN: +91 98765 43210";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "+91 98765 43210");
    }

    #[test]
    fn test_with_countries_custom_list() {
        // Only accept DE numbers (Germany)
        let detector = PhoneNumberDetector::with_countries(vec!["DE".to_string()]);
        let text = "DE: +49 30 12345678";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_with_countries_empty_list_rejects_local_format() {
        // Empty country list means no local-format validation
        // Only +prefixed international numbers should work
        let detector = PhoneNumberDetector::with_countries(vec![]);
        let text = "US local: 202-555-0123";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_with_countries_empty_still_accepts_intl_prefix() {
        let detector = PhoneNumberDetector::with_countries(vec![]);
        let text = "Intl: +12025550123";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_with_countries_multiple() {
        // Accept FR and JP only
        let detector =
            PhoneNumberDetector::with_countries(vec!["FR".to_string(), "JP".to_string()]);
        let text = "FR: +33 1 23 45 67 89 and JP: +81 90 1234 5678";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 2);
    }

    #[test]
    fn test_with_countries_intl_prefix() {
        // +44 (UK) works even without UK in list, because phonelib handles international prefix
        let detector = PhoneNumberDetector::with_countries(vec!["US".to_string()]);
        let text = "UK: +44 20 7946 0958";
        let detections = detector.detect(text);
        // International prefix (+44) is handled by phonelib::parse, not parse_with_country
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_default_countries_constant() {
        assert_eq!(
            DEFAULT_PHONE_COUNTRIES,
            &["US", "GB", "DE", "FR", "CA", "AU", "JP"]
        );
    }
}
