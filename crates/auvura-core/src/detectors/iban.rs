//! IBAN (International Bank Account Number) detector.
//!
//! Detects IBANs with mod-97 checksum validation per ISO 13616.
//! IBAN format: up to 34 alphanumeric characters
//!   - 2-letter country code (ISO 3166-1 alpha-2)
//!   - 2 check digits (mod-97)
//!   - BBAN (Basic Bank Account Number, length varies by country)

use crate::{
    detector::{Confidence, Detection, PiiDetector},
    types::PiiType,
};
use regex::Regex;
use std::sync::OnceLock;

/// IBAN detector with mod-97 checksum validation
pub struct IbanDetector {
    pattern: &'static Regex,
}

impl Default for IbanDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IbanDetector {
    pub fn new() -> Self {
        Self {
            pattern: Self::get_pattern(),
        }
    }

    fn get_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            Regex::new(r"\b[A-Z]{2}\d{2}[ -]?[A-Z0-9](?:[ -]?[A-Z0-9]){3,33}\b")
                .expect("IBAN pattern is valid")
        })
    }

    /// Validate IBAN using mod-97 checksum (ISO 13616)
    ///
    /// Algorithm:
    /// 1. Move first 4 characters to end
    /// 2. Replace letters with digits (A=10, B=11, ..., Z=35)
    /// 3. Compute mod 97 of the resulting number
    /// 4. Valid if result == 1
    fn validate_iban(iban: &str) -> bool {
        // Remove spaces and dashes
        let cleaned: String = iban
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();

        // Must be 15-34 characters
        if cleaned.len() < 15 || cleaned.len() > 34 {
            return false;
        }

        // Must start with 2 letters (country code) followed by 2 digits (check)
        let bytes = cleaned.as_bytes();
        if !bytes[0].is_ascii_uppercase()
            || !bytes[1].is_ascii_uppercase()
            || !bytes[2].is_ascii_digit()
            || !bytes[3].is_ascii_digit()
        {
            return false;
        }

        // Move first 4 chars to end
        let rearranged = format!("{}{}", &cleaned[4..], &cleaned[0..4]);

        // Replace letters with numbers (A=10, B=11, ..., Z=35)
        let numeric: String = rearranged
            .chars()
            .map(|c| {
                if c.is_ascii_digit() {
                    Some(c.to_string())
                } else if c.is_ascii_uppercase() {
                    // A=10, B=11, ..., Z=35
                    Some((c as u32 - 'A' as u32 + 10).to_string())
                } else {
                    // Lowercase should not occur, but handle gracefully
                    None
                }
            })
            .collect::<Option<Vec<_>>>()
            .map(|v| v.join(""))
            .unwrap_or_default();

        // Compute mod 97
        // Process in chunks to avoid overflow (IBAN numbers can be very large)
        let mut remainder: u64 = 0;
        for byte in numeric.bytes() {
            let digit = (byte - b'0') as u64;
            remainder = (remainder * 10 + digit) % 97;
        }

        remainder == 1
    }
}

impl PiiDetector for IbanDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::Iban
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        self.pattern
            .find_iter(text)
            .filter_map(|m| {
                let candidate = m.as_str();

                // Quick length check
                let alphanum_len: usize = candidate.chars().filter(|c| c.is_alphanumeric()).count();
                if !(15..=34).contains(&alphanum_len) {
                    return None;
                }

                // Must start with a valid country code (2 uppercase letters)
                let first_chars: Vec<char> = candidate.chars().take(2).collect();
                if first_chars.len() < 2
                    || !first_chars[0].is_ascii_uppercase()
                    || !first_chars[1].is_ascii_uppercase()
                {
                    return None;
                }

                // Validate with mod-97 checksum
                if !Self::validate_iban(candidate) {
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
                    pii_type: PiiType::Iban,
                    confidence: self.confidence(),
                    start,
                    end,
                    original: candidate.to_string(),
                })
            })
            .collect()
    }

    fn anchor_patterns(&self) -> Vec<&'static str> {
        // No reliable single anchor for IBANs — fall back to full regex scan
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_iban_de() {
        // German IBAN: DE89 3704 0044 0532 0130 00
        let detector = IbanDetector::new();
        let detections = detector.detect("IBAN: DE89370400440532013000");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "DE89370400440532013000");
    }

    #[test]
    fn test_valid_iban_with_spaces() {
        let detector = IbanDetector::new();
        let detections = detector.detect("IBAN: DE89 3704 0044 0532 0130 00");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_valid_iban_gb() {
        // UK IBAN: GB29 NWBK 6016 1331 9268 19
        let detector = IbanDetector::new();
        let detections = detector.detect("Sort: GB29NWBK60161331926819");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_valid_iban_fr() {
        // French IBAN: FR76 3000 6000 0112 3456 7890 189
        let detector = IbanDetector::new();
        let detections = detector.detect("Compte: FR7630006000011234567890189");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_invalid_iban_checksum() {
        // Wrong check digits
        let detector = IbanDetector::new();
        let detections = detector.detect("IBAN: DE00370400440532013000");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_iban_too_short() {
        let detector = IbanDetector::new();
        let detections = detector.detect("IBAN: DE8937040044");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_iban_too_long() {
        let detector = IbanDetector::new();
        // 35+ alphanumeric chars
        let detections = detector.detect("IBAN: DE893704004405320130000000000000000X");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_not_iban_letters_only() {
        let detector = IbanDetector::new();
        let detections = detector.detect("NOTANIBAN ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_iban_word_boundary() {
        let detector = IbanDetector::new();
        // Should not match inside a longer word
        let detections = detector.detect("XDE89370400440532013000Y");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_iban_in_sentence() {
        let detector = IbanDetector::new();
        let detections = detector.detect("Please transfer to DE89370400440532013000 by Friday.");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_iban_with_dashes() {
        let detector = IbanDetector::new();
        let detections = detector.detect("IBAN: DE89-3704-0044-0532-0130-00");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_iban_lowercase_treated_as_invalid() {
        // IBANs should be uppercase; lowercase might indicate non-IBAN
        let detector = IbanDetector::new();
        let detections = detector.detect("iban: de89370400440532013000");
        assert_eq!(detections.len(), 0);
    }
}
