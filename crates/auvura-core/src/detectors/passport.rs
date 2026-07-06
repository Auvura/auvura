//! Passport number detector.
//!
//! Detects passport numbers from various countries using common patterns.
//! Passport numbers vary significantly by country, so this detector uses
//! heuristic patterns that catch the most common formats while minimizing
//! false positives.

use crate::{
    detector::{Detection, PiiDetector},
    types::PiiType,
};
use regex::Regex;
use std::sync::OnceLock;

/// Passport number detector
pub struct PassportDetector {
    pattern: &'static Regex,
}

impl Default for PassportDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PassportDetector {
    pub fn new() -> Self {
        Self {
            pattern: Self::get_pattern(),
        }
    }

    fn get_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            // Common passport number patterns:
            // - US: 9 digits (1 or 2 letters + 7-8 digits also common)
            // - UK: 9 characters (letters + digits, or all digits)
            // - EU: 8-9 digits or 2 letters + 7 digits
            // - General: 6-12 alphanumeric characters, often starting with letter(s)
            //
            // Use two patterns: one for letter-prefixed, one for all-digits
            Regex::new(r"\b(?:[A-Z]{1,2}\d{6,10}|\d{6,10}[A-Z]?)\b")
                .expect("Passport pattern is valid")
        })
    }

    /// Check if the candidate looks like a valid passport number
    fn is_valid_passport(candidate: &str) -> bool {
        let cleaned: String = candidate.chars().filter(|c| !c.is_whitespace()).collect();

        // Length check: 6-12 characters
        if cleaned.len() < 6 || cleaned.len() > 12 {
            return false;
        }

        // Must contain at least one digit
        if !cleaned.chars().any(|c| c.is_ascii_digit()) {
            return false;
        }

        // If starts with letters, validate format
        if cleaned
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
        {
            // Count letters at start
            let mut letter_count = 0;
            for c in cleaned.chars() {
                if c.is_ascii_uppercase() {
                    letter_count += 1;
                } else {
                    break;
                }
            }

            // Must have 1-2 leading letters
            if !(1..=2).contains(&letter_count) {
                return false;
            }

            // Rest must be digits
            let digit_part = &cleaned[letter_count..];
            if !digit_part.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }

            // Digit part should be 6-10 digits
            if digit_part.len() < 6 || digit_part.len() > 10 {
                return false;
            }
        } else {
            // All digits or ends with letter - just check length
            let digit_count = cleaned.chars().filter(|c| c.is_ascii_digit()).count();
            if !(6..=10).contains(&digit_count) {
                return false;
            }
        }

        true
    }
}

impl PiiDetector for PassportDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::PassportNumber
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        self.pattern
            .find_iter(text)
            .filter_map(|m| {
                let candidate = m.as_str();

                if !Self::is_valid_passport(candidate) {
                    return None;
                }

                // Check word boundaries
                let start = m.start();
                let end = m.end();
                let before_ok = start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric();
                let after_ok = end >= text.len() || !text.as_bytes()[end].is_ascii_alphanumeric();
                if !before_ok || !after_ok {
                    return None;
                }

                Some(Detection {
                    pii_type: PiiType::PassportNumber,
                    start,
                    end,
                    original: candidate.to_string(),
                })
            })
            .collect()
    }

    fn anchor_patterns(&self) -> Vec<&'static str> {
        vec![
            "passport",
            "passport no",
            "passport number",
            "travel document",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_us_passport() {
        let detector = PassportDetector::new();
        let detections = detector.detect("Passport: AB1234567");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "AB1234567");
    }

    #[test]
    fn test_us_passport_long() {
        let detector = PassportDetector::new();
        let detections = detector.detect("Passport: A123456789");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_uk_passport() {
        let detector = PassportDetector::new();
        let detections = detector.detect("Travel doc: 123456789");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_all_digits_passport() {
        let detector = PassportDetector::new();
        // UK passports can be all digits
        let detections = detector.detect("Passport: 987654321");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_eu_passport() {
        let detector = PassportDetector::new();
        let detections = detector.detect("Passport No: L01234567");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_passport_too_short() {
        let detector = PassportDetector::new();
        let detections = detector.detect("Passport: AB12345");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_passport_no_letters() {
        let detector = PassportDetector::new();
        // All-digit passports are valid (e.g., UK passports)
        let detections = detector.detect("Code: 1234567890");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_passport_all_digits_too_short() {
        let detector = PassportDetector::new();
        // 5 digits is too short for passport
        let detections = detector.detect("Code: 12345");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_passport_in_sentence() {
        let detector = PassportDetector::new();
        let detections = detector.detect("My passport AB1234567 expires soon.");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_passport_word_boundary() {
        let detector = PassportDetector::new();
        // Should not match in middle of word
        let detections = detector.detect("XAB1234567Y");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_passport_with_context() {
        let detector = PassportDetector::new();
        let detections = detector
            .detect("Travel Document: 987654321\nPassport Number: K98765432\nIssued: 2020-01-01");
        assert!(detections.len() >= 1);
    }
}
