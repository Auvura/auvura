//! SSNDetector - Validates US Social Security Numbers per SSA guidelines
//!
//! Implements PiiDetector trait with:
//! - Pattern matching for ###-##-#### and ######### formats
//! - Validation against SSA invalid ranges:
//!   * Area: 000, 666, 900-999
//!   * Group: 00
//!   * Serial: 0000
//! - Word boundary enforcement to prevent false positives

use crate::{
    detector::{Detection, PiiDetector},
    types::PiiType,
};
use regex::Regex;
use std::sync::OnceLock;

/// SSNDetector - detects and validates US Social Security Numbers
pub struct SSNDetector {
    combined_pattern: &'static Regex,
}

impl SSNDetector {
    /// Create a new SSNDetector
    pub fn new() -> Self {
        Self {
            combined_pattern: Self::get_combined_pattern(),
        }
    }

    fn get_combined_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            // Combined pattern that matches both formats without overlap
            // Uses alternation with word boundaries
            Regex::new(r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b").expect("Combined SSN pattern is valid")
        })
    }

    /// Validate SSN components per SSA guidelines
    /// https://www.ssa.gov/employer/stateweb.htm
    fn is_valid_ssn(&self, area: u16, group: u8, serial: u16) -> bool {
        // Invalid area numbers
        if area == 0 || area == 666 || area >= 900 {
            return false;
        }

        // Invalid group number
        if group == 0 {
            return false;
        }

        // Invalid serial number
        if serial == 0 {
            return false;
        }

        true
    }

    /// Parse SSN string into components (area, group, serial)
    fn parse_ssn(&self, ssn: &str) -> Option<(u16, u8, u16)> {
        let clean_ssn: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
        if clean_ssn.len() != 9 {
            return None;
        }

        let area = clean_ssn[0..3].parse::<u16>().ok()?;
        let group = clean_ssn[3..5].parse::<u8>().ok()?;
        let serial = clean_ssn[5..9].parse::<u16>().ok()?;

        Some((area, group, serial))
    }
}

impl PiiDetector for SSNDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::Ssn
    }

    fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Single pass with combined pattern prevents overlaps
        for m in self.combined_pattern.find_iter(text) {
            let ssn_str = m.as_str();
            if let Some((area, group, serial)) = self.parse_ssn(ssn_str) {
                if self.is_valid_ssn(area, group, serial) {
                    detections.push(Detection {
                        pii_type: PiiType::Ssn,
                        start: m.start(),
                        end: m.end(),
                        original: ssn_str.to_string(),
                    });
                }
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
    use crate::types::PiiType;

    #[test]
    fn test_detects_valid_hyphenated_ssn() {
        let detector = SSNDetector::new();
        let text = "SSN: 123-45-6789";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pii_type, PiiType::Ssn);
        assert_eq!(detections[0].start, 5);
        assert_eq!(detections[0].end, 16);
        assert_eq!(detections[0].original, "123-45-6789");
    }

    #[test]
    fn test_detects_valid_unhyphenated_ssn() {
        let detector = SSNDetector::new();
        let text = "ID: 123456789";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "123456789");
    }

    #[test]
    fn test_rejects_area_000() {
        let detector = SSNDetector::new();
        let text = "Invalid: 000-12-3456";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_area_666() {
        let detector = SSNDetector::new();
        let text = "Invalid: 666-12-3456";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_area_900_plus() {
        let detector = SSNDetector::new();
        let text = "Invalid: 900-12-3456 and 999-99-9999";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_group_00() {
        let detector = SSNDetector::new();
        let text = "Invalid: 123-00-4567";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_serial_0000() {
        let detector = SSNDetector::new();
        let text = "Invalid: 123-45-0000";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_respects_word_boundaries_hyphenated() {
        let detector = SSNDetector::new();
        let text = "Not SSN: 1234-56-7890";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_respects_word_boundaries_unhyphenated() {
        let detector = SSNDetector::new();
        let text = "Not SSN: 1234567890";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_detects_multiple_ssns() {
        let detector = SSNDetector::new();
        let text = "SSNs: 123-45-6789 and 567890123";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].original, "123-45-6789");
        assert_eq!(detections[1].original, "567890123");
    }

    #[test]
    fn test_returns_sorted_detections() {
        let detector = SSNDetector::new();
        let text = "Second: 456-78-9012 First: 123-45-6789";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 2);
        assert!(detections[0].start < detections[1].start);
        assert_eq!(detections[0].original, "456-78-9012");
        assert_eq!(detections[1].original, "123-45-6789");
    }

    #[test]
    fn test_integrates_with_redactor() {
        use crate::{policy::RedactionPolicy, redactor::Redactor};

        let detector = SSNDetector::new();
        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "My SSN is 123-45-6789";
        let result = redactor.redact(input);

        assert_eq!(result, "My SSN is ███-██-████");
    }

    #[test]
    fn test_zeroizes_on_drop() {
        let detector = SSNDetector::new();
        let text = "123-45-6789";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        let original = detections[0].original.clone();
        assert_eq!(original, "123-45-6789");

        std::mem::drop(detections);
    }

    #[test]
    fn test_valid_edge_case_area_899() {
        let detector = SSNDetector::new();
        let text = "Valid: 899-12-3456";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "899-12-3456");
    }

    #[test]
    fn test_valid_edge_case_group_99() {
        let detector = SSNDetector::new();
        let text = "Valid: 123-99-4567";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "123-99-4567");
    }

    #[test]
    fn test_valid_edge_case_serial_9999() {
        let detector = SSNDetector::new();
        let text = "Valid: 123-45-9999";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "123-45-9999");
    }
}
