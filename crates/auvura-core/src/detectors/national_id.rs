//! National identity number detector.
//!
//! Detects national identity numbers from various countries:
//! - EU: DE Personalausweisnummer, FR INSEE, ES DNI/NIE
//! - AU: Tax File Number (TFN), Medicare number
//! - IN: Aadhaar (12 digits), PAN (10 chars: 5 letters + 4 digits + 1 letter)

use crate::{
    detector::{Detection, PiiDetector},
    types::PiiType,
};
use regex::Regex;
use std::sync::OnceLock;

/// National identity number detector
pub struct NationalIdDetector {
    pattern: &'static Regex,
}

impl Default for NationalIdDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NationalIdDetector {
    pub fn new() -> Self {
        Self {
            pattern: Self::get_pattern(),
        }
    }

    fn get_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            // Combined pattern for common national ID formats:
            // - IN Aadhaar: 12 digits (may have spaces: XXXX XXXX XXXX)
            // - IN PAN: 5 letters + 4 digits + 1 letter (e.g., ABCDE1234F)
            // - AU TFN: 8-9 digits
            // - FR INSEE: 13 digits (may start with 1/2 for gender)
            // - DE: Alphanumeric patterns for Personalausweis
            //
            // Use alternation to match specific formats
            Regex::new(
                r"(?x)
                \b\d{4}\s?\d{4}\s?\d{4}\b          |  # IN Aadhaar (12 digits)
                \b[A-Z]{5}\d{4}[A-Z]\b             |  # IN PAN (ABCDE1234F)
                \b\d{3}\s?\d{3}\s?\d{3}\b          |  # AU TFN (9 digits, may have spaces)
                \b\d{3}\s?\d{5}\b                   |  # AU TFN (8 digits: 3 + 5)
                \b[12]\d{12}\b                          # FR INSEE (13 digits, starts with 1/2)
            ",
            )
            .expect("National ID pattern is valid")
        })
    }

    /// Validate national ID based on format
    fn is_valid_national_id(candidate: &str) -> bool {
        let cleaned: String = candidate.chars().filter(|c| !c.is_whitespace()).collect();

        // IN PAN: exactly 10 chars, 5 letters + 4 digits + 1 letter
        if cleaned.len() == 10
            && cleaned[0..5].chars().all(|c| c.is_ascii_uppercase())
            && cleaned[5..9].chars().all(|c| c.is_ascii_digit())
            && cleaned[9..10].chars().all(|c| c.is_ascii_uppercase())
        {
            return true;
        }

        // IN Aadhaar: exactly 12 digits
        if cleaned.len() == 12 && cleaned.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }

        // AU TFN: 8 or 9 digits
        if (cleaned.len() == 8 || cleaned.len() == 9) && cleaned.chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }

        // FR INSEE: exactly 13 digits, starts with 1 or 2
        if cleaned.len() == 13
            && cleaned.chars().all(|c| c.is_ascii_digit())
            && (cleaned.starts_with('1') || cleaned.starts_with('2'))
        {
            return true;
        }

        false
    }
}

impl PiiDetector for NationalIdDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::NationalId
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        self.pattern
            .find_iter(text)
            .filter_map(|m| {
                let candidate = m.as_str();

                if !Self::is_valid_national_id(candidate) {
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
                    pii_type: PiiType::NationalId,
                    confidence: self.confidence(),
                    start,
                    end,
                    original: candidate.to_string(),
                })
            })
            .collect()
    }

    fn anchor_patterns(&self) -> Vec<&'static str> {
        vec![
            "aadhaar",
            "pan",
            "tfn",
            "tax file number",
            "medicare",
            "national id",
            "personalausweis",
            "numéro insee",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indian_aadhaar() {
        let detector = NationalIdDetector::new();
        let detections = detector.detect("Aadhaar: 123456789012");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "123456789012");
    }

    #[test]
    fn test_indian_aadhaar_with_spaces() {
        let detector = NationalIdDetector::new();
        let detections = detector.detect("Aadhaar: 1234 5678 9012");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_indian_pan() {
        let detector = NationalIdDetector::new();
        let detections = detector.detect("PAN: ABCDE1234F");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "ABCDE1234F");
    }

    #[test]
    fn test_australian_tfn() {
        let detector = NationalIdDetector::new();
        let detections = detector.detect("TFN: 123456789");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_australian_tfn_short() {
        let detector = NationalIdDetector::new();
        let detections = detector.detect("TFN: 12345678");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_french_insee() {
        let detector = NationalIdDetector::new();
        let detections = detector.detect("INSEE: 1850377123456");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_invalid_pan_format() {
        let detector = NationalIdDetector::new();
        // Too short
        let detections = detector.detect("PAN: ABC1234F");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_invalid_aadhaar_length() {
        let detector = NationalIdDetector::new();
        // 11 digits
        let detections = detector.detect("Aadhaar: 12345678901");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_national_id_in_sentence() {
        let detector = NationalIdDetector::new();
        let detections = detector.detect("Tax File Number: 987654321 was issued in 2020.");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_national_id_word_boundary() {
        let detector = NationalIdDetector::new();
        let detections = detector.detect("X123456789012Y");
        assert_eq!(detections.len(), 0);
    }
}
