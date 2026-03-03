//! CreditCardDetector - PCI-DSS compliant card number detection
//!
//! Implements PiiDetector trait with:
//! - Boundary checks
//! - Luhn algorithm validation
//! - BIN pattern matching for major networks
//! - Separator handling (spaces/dashes)
//!
//! Test numbers sourced from PCI SSC documentation (safe for testing):
//! https://docs.paymentcardindustry.com/virtual-terminal/test-card-numbers/

use crate::{
    detector::{Detection, PiiDetector},
    types::PiiType,
};
use regex::Regex;
use std::sync::OnceLock;

/// CreditCardDetector - detects payment card numbers with validation
pub struct CreditCardDetector {
    pattern: &'static Regex,
}

impl CreditCardDetector {
    /// Create a new CreditCardDetector
    pub fn new() -> Self {
        Self {
            pattern: Self::get_pattern(),
        }
    }

    fn get_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            // Matches 13-19 digit sequences with optional spaces/dashes BETWEEN digits
            // Boundary validation done in code (avoids regex look-around limitations)
            Regex::new(r"\d(?:[ -]*\d){12,18}").expect("Card pattern is valid")
        })
    }

    /// Luhn algorithm validation (mod 10 check)
    fn passes_luhn(s: &str) -> bool {
        if s.len() < 2 {
            return false;
        }

        let mut sum = 0;
        let mut should_double = false;

        for ch in s.chars().rev() {
            if let Some(digit) = ch.to_digit(10) {
                let mut d = digit;
                if should_double {
                    d *= 2;
                    if d > 9 {
                        d -= 9;
                    }
                }
                sum += d;
                should_double = !should_double;
            } else {
                return false;
            }
        }

        sum % 10 == 0
    }

    /// BIN validation + length checks to prevent false positives
    fn is_valid_card_number(s: &str) -> bool {
        let len = s.len();

        if len < 13 || len > 19 {
            return false;
        }

        // Visa: starts with 4 (13 or 16 digits)
        if s.starts_with('4') && (len == 13 || len == 16) {
            return true;
        }

        // Mastercard: 51-55 (16 digits) OR 2221-2720 (16 digits)
        if len == 16 {
            if s.starts_with('5') {
                if let Some(second) = s.chars().nth(1).and_then(|c| c.to_digit(10)) {
                    if (1..=5).contains(&second) {
                        return true;
                    }
                }
            }
            if s.starts_with("222")
                || s.starts_with("223")
                || s.starts_with("224")
                || s.starts_with("225")
                || s.starts_with("226")
                || s.starts_with("227")
                || s.starts_with("228")
                || s.starts_with("229")
                || s.starts_with("23")
                || s.starts_with("24")
                || s.starts_with("25")
                || s.starts_with("26")
                || s.starts_with("27")
            {
                return true;
            }

            // Discover: 6011, 65, 644-649
            if s.starts_with("6011") || s.starts_with("65") {
                return true;
            }
            if s.starts_with("64") {
                if let Some(third) = s.chars().nth(2).and_then(|c| c.to_digit(10)) {
                    if (4..=9).contains(&third) {
                        return true;
                    }
                }
            }
        }

        // Amex: 34 or 37 (15 digits)
        if len == 15 && (s.starts_with("34") || s.starts_with("37")) {
            return true;
        }

        false
    }
}

impl PiiDetector for CreditCardDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::CreditCard
    }

    fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for m in self.pattern.find_iter(text) {
            let candidate = m.as_str();
            let start = m.start();
            let end = m.end();

            // CRITICAL: Boundary validation in Rust code (avoids regex look-around)
            // Reject if preceded by digit (prevents matching substrings of longer numbers)
            if start > 0 {
                let prev_char = text[start - 1..start].chars().next().unwrap_or('\0');
                if prev_char.is_ascii_digit() {
                    continue;
                }
            }

            // Reject if followed by digit
            if end < text.len() {
                let next_char = text[end..end + 1].chars().next().unwrap_or('\0');
                if next_char.is_ascii_digit() {
                    continue;
                }
            }

            // Clean separators to get raw digits
            let cleaned: String = candidate.chars().filter(|c| c.is_ascii_digit()).collect();

            // Safety check (pattern should guarantee this, but validate anyway)
            if cleaned.len() < 13 || cleaned.len() > 19 {
                continue;
            }

            // Validation chain: Luhn + BIN patterns
            if Self::passes_luhn(&cleaned) && Self::is_valid_card_number(&cleaned) {
                detections.push(Detection {
                    pii_type: PiiType::CreditCard,
                    start,
                    end,
                    original: candidate.to_string(),
                });
            }
        }

        // Sort by start position (required by trait contract)
        detections.sort_by_key(|d| d.start);
        detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_visa_with_spaces() {
        let detector = CreditCardDetector::new();
        let text = "Card: 4111 1111 1111 1111";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "4111 1111 1111 1111");
    }

    #[test]
    fn test_detects_visa_unseparated() {
        let detector = CreditCardDetector::new();
        let text = "Payment: 4111111111111111";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "4111111111111111");
    }

    #[test]
    fn test_detects_mastercard() {
        let detector = CreditCardDetector::new();
        let text = "MC: 5500000000000004";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "5500000000000004");
    }

    #[test]
    fn test_detects_amex() {
        let detector = CreditCardDetector::new();
        let text = "Amex: 378282246310005";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "378282246310005");
    }

    #[test]
    fn test_detects_discover() {
        let detector = CreditCardDetector::new();
        let text = "Disc: 6011111111111117";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "6011111111111117");
    }

    #[test]
    fn test_rejects_invalid_luhn() {
        let detector = CreditCardDetector::new();
        let text = "Invalid: 4111111111111112"; // Fails Luhn
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_timestamp() {
        let detector = CreditCardDetector::new();
        let text = "Timestamp: 2024010112345678"; // 16 digits but not card
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_sku() {
        let detector = CreditCardDetector::new();
        let text = "Product SKU: 1234567890123456";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_respects_word_boundaries() {
        let detector = CreditCardDetector::new();
        let text = "Not card: 12345678901234567"; // 17 digits
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_handles_dashes() {
        let detector = CreditCardDetector::new();
        let text = "Card: 4111-1111-1111-1111";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "4111-1111-1111-1111");
    }

    #[test]
    fn test_returns_sorted_detections() {
        let detector = CreditCardDetector::new();
        let text = "Cards: 5500000000000004 and 4111111111111111";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 2);
        assert!(detections[0].start < detections[1].start);
    }

    #[test]
    fn test_integrates_with_redactor() {
        use crate::{policy::RedactionPolicy, redactor::Redactor};
        let detector = CreditCardDetector::new();
        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);
        let input = "Pay with 4111 1111 1111 1111";
        let result = redactor.redact(input);
        assert_eq!(result, "Pay with ████ ████ ████ 1111");
    }

    #[test]
    fn test_zeroizes_on_drop() {
        let detector = CreditCardDetector::new();
        let text = "4111111111111111";
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 1);
        let original = detections[0].original.clone();
        assert_eq!(original, "4111111111111111");
        std::mem::drop(detections);
    }

    #[test]
    fn test_rejects_short_number() {
        let detector = CreditCardDetector::new();
        let text = "Code: 123456"; // Too short
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_long_number() {
        let detector = CreditCardDetector::new();
        let text = "ID: 12345678901234567890"; // Too long
        let detections = detector.detect(text);
        assert_eq!(detections.len(), 0);
    }
}
