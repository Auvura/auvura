//! Physical address detector.
//!
//! Detects physical street addresses using heuristic patterns.
//! This is a heuristic detector that looks for common address patterns
//! (street numbers, street names, city/state/zip). It's less precise than
//! the other detectors but useful for catching obvious addresses.

use crate::{
    detector::{Detection, PiiDetector},
    types::PiiType,
};
use regex::Regex;
use std::sync::OnceLock;

/// Physical address detector
pub struct AddressDetector {
    pattern: &'static Regex,
}

impl Default for AddressDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressDetector {
    pub fn new() -> Self {
        Self {
            pattern: Self::get_pattern(),
        }
    }

    fn get_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            // Address pattern: street number + street name + street type
            // Uses case-insensitive matching and verbose mode for readability
            Regex::new(
                r"(?ix)
                \b\d{1,6}\s+
                \w+(?:\s+\w+)*
                \s+(?:street|st|avenue|ave|boulevard|blvd|drive|dr|lane|ln|
                    road|rd|court|ct|place|pl|way|circle|trail|trl|
                    parkway|pkwy|highway|hwy|terrace|ter)
                (?:\s+(?:suite|ste|apt|unit|floor|fl)\s+\S+)?
                (?:,\s*\w+(?:\s+\w+)*?)?
                (?:,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?
                \b
            ",
            )
            .expect("Address pattern is valid")
        })
    }

    /// Check if the candidate looks like a valid address
    fn is_valid_address(candidate: &str) -> bool {
        let trimmed = candidate.trim();

        // Must start with a digit (street number)
        if !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
            return false;
        }

        // Must contain at least one street type word (case-insensitive)
        let street_types = [
            "street",
            "st",
            "avenue",
            "ave",
            "boulevard",
            "blvd",
            "drive",
            "dr",
            "lane",
            "ln",
            "road",
            "rd",
            "court",
            "ct",
            "place",
            "pl",
            "way",
            "circle",
            "trail",
            "trl",
            "parkway",
            "pkwy",
            "highway",
            "hwy",
            "terrace",
            "ter",
        ];

        let lower = trimmed.to_lowercase();
        let has_street_type = street_types.iter().any(|st| {
            // Use word boundary matching for each street type
            let pattern = format!(r"\b{}\b", regex::escape(st));
            Regex::new(&pattern)
                .map(|re| re.is_match(&lower))
                .unwrap_or(false)
        });

        if !has_street_type {
            return false;
        }

        // Length check: at least 8 characters
        if trimmed.len() < 8 {
            return false;
        }

        true
    }
}

impl PiiDetector for AddressDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::PhysicalAddress
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        self.pattern
            .find_iter(text)
            .filter_map(|m| {
                let candidate = m.as_str();

                if !Self::is_valid_address(candidate) {
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
                    pii_type: PiiType::PhysicalAddress,
                    start,
                    end,
                    original: candidate.to_string(),
                })
            })
            .collect()
    }

    fn anchor_patterns(&self) -> Vec<&'static str> {
        vec![
            "address",
            "street",
            "avenue",
            "boulevard",
            "drive",
            "road",
            "lane",
            "court",
            "place",
            "way",
            "residence",
            "located at",
            "mailing address",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_address() {
        let detector = AddressDetector::new();
        let detections = detector.detect("Address: 123 Main Street");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "123 Main Street");
    }

    #[test]
    fn test_address_with_city() {
        let detector = AddressDetector::new();
        let detections = detector.detect("Location: 456 Oak Avenue, Springfield, IL 62704");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_address_abbreviation() {
        let detector = AddressDetector::new();
        let detections = detector.detect("Send to: 789 Elm Blvd, Suite 100");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_address_in_sentence() {
        let detector = AddressDetector::new();
        let detections = detector.detect("Please deliver to 321 Pine Road by Monday.");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_address_no_street_type() {
        let detector = AddressDetector::new();
        let detections = detector.detect("Building: 123 Something");
        // "Something" is not a recognized street type
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_address_too_short() {
        let detector = AddressDetector::new();
        let detections = detector.detect("123 Main");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_address_word_boundary() {
        let detector = AddressDetector::new();
        // Should not match inside a longer word
        let detections = detector.detect("X123 Main StreetY");
        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_address_with_zip() {
        let detector = AddressDetector::new();
        let detections = detector.detect("Office: 500 Corporate Dr, Austin, TX 78701");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_address_case_insensitive() {
        let detector = AddressDetector::new();
        let detections = detector.detect("office: 123 main street");
        assert_eq!(detections.len(), 1);
    }
}
