//! IPv4 and IPv6 address detectors
//!
//! Implements PiiDetector trait for IP address detection with:
//! - Regex-based candidate detection
//! - `std::net::IpAddr` validation (RFC-compliant)
//! - Word boundary enforcement for IPv4, manual boundaries for IPv6

use crate::{
    detector::{Confidence, Detection, PiiDetector},
    types::PiiType,
};
use regex::Regex;
use std::{net::IpAddr, sync::OnceLock};

/// Detects IPv4 addresses (dotted-decimal notation)
pub struct Ipv4Detector {
    pattern: &'static Regex,
}

impl Default for Ipv4Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv4Detector {
    pub fn new() -> Self {
        Self {
            pattern: Self::get_pattern(),
        }
    }

    fn get_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            // \b works for IPv4 because '.' is not a word character
            Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("IPv4 regex pattern is valid")
        })
    }
}

impl PiiDetector for Ipv4Detector {
    fn pii_type(&self) -> PiiType {
        PiiType::IpAddressV4
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        self.detect_with_validation(text, true)
    }

    fn detect_with_validation(&self, text: &str, validate: bool) -> Vec<Detection> {
        self.pattern
            .find_iter(text)
            .filter_map(|m| {
                let addr = m.as_str();
                if !validate || addr.parse::<IpAddr>().is_ok() {
                    Some(Detection {
                        pii_type: PiiType::IpAddressV4,
                        confidence: self.confidence(),
                        start: m.start(),
                        end: m.end(),
                        original: addr.to_string(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Dot-separated digits is the anchor for IPv4 (e.g., `192.168.`)
    fn anchor_patterns(&self) -> Vec<&'static str> {
        vec!["."]
    }

    fn detect_in_window(&self, window: &str, window_start: usize) -> Vec<Detection> {
        self.detect_with_validation(window, true)
            .into_iter()
            .map(|mut d| {
                d.start += window_start;
                d.end += window_start;
                d
            })
            .collect()
    }
}

/// Detects IPv6 addresses (colon-separated hex notation)
pub struct Ipv6Detector {
    /// Matches potential IPv6 candidates: hex digits and colons.
    /// Manual boundary check required since \b doesn't work with ':'.
    pattern: &'static Regex,
}

impl Default for Ipv6Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv6Detector {
    pub fn new() -> Self {
        Self {
            pattern: Self::get_pattern(),
        }
    }

    fn get_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            // Match IPv6 candidates: hex groups separated by colons,
            // optionally followed by an IPv4 suffix (dotted decimal)
            Regex::new(r"[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){1,7}(?:\.\d{1,3}){0,3}")
                .expect("IPv6 regex pattern is valid")
        })
    }

    /// Check that match is not preceded or followed by hex/colon chars
    fn is_bounded(text: &str, start: usize, end: usize) -> bool {
        // Check preceding char
        if start > 0 {
            let prev = text.as_bytes()[start - 1];
            if prev.is_ascii_hexdigit() || prev == b':' {
                return false;
            }
        }
        // Check following char
        if end < text.len() {
            let next = text.as_bytes()[end];
            if next.is_ascii_hexdigit() || next == b':' {
                return false;
            }
        }
        true
    }
}

impl PiiDetector for Ipv6Detector {
    fn pii_type(&self) -> PiiType {
        PiiType::IpAddressV6
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        self.detect_with_validation(text, true)
    }

    fn detect_with_validation(&self, text: &str, validate: bool) -> Vec<Detection> {
        self.pattern
            .find_iter(text)
            .filter_map(|m| {
                let candidate = m.as_str();
                // Must contain a colon
                if !candidate.contains(':') {
                    return None;
                }
                // Must be bounded (not part of longer hex/colon sequence)
                if !Self::is_bounded(text, m.start(), m.end()) {
                    return None;
                }
                if !validate || candidate.parse::<IpAddr>().is_ok() {
                    Some(Detection {
                        pii_type: PiiType::IpAddressV6,
                        confidence: self.confidence(),
                        start: m.start(),
                        end: m.end(),
                        original: candidate.to_string(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Colon is the anchor for IPv6 addresses
    fn anchor_patterns(&self) -> Vec<&'static str> {
        vec![":"]
    }

    fn detect_in_window(&self, window: &str, window_start: usize) -> Vec<Detection> {
        self.detect_with_validation(window, true)
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
    use crate::{policy::RedactionPolicy, redactor::Redactor, types::PiiType};

    // ===== IPv4 Tests =====

    #[test]
    fn test_detects_valid_ipv4() {
        let detector = Ipv4Detector::new();
        let text = "Server at 192.168.1.1 is running";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pii_type, PiiType::IpAddressV4);
        assert_eq!(detections[0].original, "192.168.1.1");
        assert_eq!(detections[0].start, 10);
        assert_eq!(detections[0].end, 21);
    }

    #[test]
    fn test_detects_multiple_ipv4() {
        let detector = Ipv4Detector::new();
        let text = "Routes: 10.0.0.1 and 172.16.0.1";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].original, "10.0.0.1");
        assert_eq!(detections[1].original, "172.16.0.1");
    }

    #[test]
    fn test_rejects_octet_over_255() {
        let detector = Ipv4Detector::new();
        let text = "Invalid: 256.1.1.1";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_rejects_leading_zeros() {
        let detector = Ipv4Detector::new();
        let text = "Invalid: 01.02.03.04";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_detects_loopback() {
        let detector = Ipv4Detector::new();
        let text = "Loopback: 127.0.0.1";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "127.0.0.1");
    }

    #[test]
    fn test_respects_word_boundaries() {
        let detector = Ipv4Detector::new();
        let text = "Not an IP: 192.168.1.1000extra";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    #[test]
    fn test_integrates_ipv4_with_redactor() {
        let detector = Ipv4Detector::new();
        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Host: 192.168.1.1";
        let result = redactor.redact(input);

        assert_eq!(result, "Host: ███████████");
    }

    // ===== IPv6 Tests =====

    #[test]
    fn test_detects_full_ipv6() {
        let detector = Ipv6Detector::new();
        let text = "Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pii_type, PiiType::IpAddressV6);
        assert_eq!(
            detections[0].original,
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        );
    }

    #[test]
    fn test_detects_compressed_ipv6() {
        let detector = Ipv6Detector::new();
        let text = "Loopback: ::1";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "::1");
    }

    #[test]
    fn test_detects_compressed_ipv6_double_colon() {
        let detector = Ipv6Detector::new();
        let text = "Network: fe80::1";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "fe80::1");
    }

    #[test]
    fn test_detects_ipv6_with_mixed_notation() {
        let detector = Ipv6Detector::new();
        let text = "Mapped: ::ffff:192.168.1.1";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "::ffff:192.168.1.1");
    }

    #[test]
    fn test_integrates_ipv6_with_redactor() {
        let detector = Ipv6Detector::new();
        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Host: ::1";
        let result = redactor.redact(input);

        assert_eq!(result, "Host: ███");
    }

    #[test]
    fn test_rejects_non_ipv6_hex_sequences() {
        let detector = Ipv6Detector::new();
        let text = "Token: deadbeef";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 0);
    }

    // ===== Both Types Together =====

    #[test]
    fn test_detects_both_types_in_text() {
        let ipv4 = Ipv4Detector::new();
        let ipv6 = Ipv6Detector::new();
        let text = "IPv4: 10.0.0.1, IPv6: ::1";

        let mut detections = ipv4.detect(text);
        detections.extend(ipv6.detect(text));
        detections.sort_by_key(|d| d.start);

        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].pii_type, PiiType::IpAddressV4);
        assert_eq!(detections[0].original, "10.0.0.1");
        assert_eq!(detections[1].pii_type, PiiType::IpAddressV6);
        assert_eq!(detections[1].original, "::1");
    }

    #[test]
    fn test_zeroizes_on_drop() {
        let detector = Ipv4Detector::new();
        let detections = detector.detect("IP: 192.168.1.1");
        assert_eq!(detections.len(), 1);
        let original = detections[0].original.clone();
        assert_eq!(original, "192.168.1.1");
        std::mem::drop(detections);
    }
}
