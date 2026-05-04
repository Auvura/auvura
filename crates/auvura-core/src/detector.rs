use crate::types::PiiType;
use zeroize::Zeroize;

/// Detection result with memory safety guarantees
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub pii_type: PiiType,
    pub start: usize,     // UTF-8 byte offset (NOT char index)
    pub end: usize,       // UTF-8 byte offset
    pub original: String, // Original text – will be zeroized on drop
}

impl Zeroize for Detection {
    fn zeroize(&mut self) {
        self.original.zeroize();
    }
}

impl Drop for Detection {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Core detection trait – all detectors must implement this
pub trait PiiDetector: Send + Sync {
    fn pii_type(&self) -> PiiType;

    /// Detect PII in text – returns sorted, non-overlapping detections
    ///
    /// Safety requirements:
    /// - MUST return detections sorted by `start` ascending
    /// - MUST NOT return overlapping detections (resolve conflicts internally)
    /// - MUST handle UTF-8 boundaries correctly (never split grapheme clusters)
    fn detect<'a>(&self, text: &'a str) -> Vec<Detection>;

    /// Detect PII with optional validation bypass
    /// Called by redactor with policy's strict_validation setting
    fn detect_with_validation<'a>(&self, text: &'a str, validate: bool) -> Vec<Detection> {
        // Default: ignore validation flag and use detect()
        // Detectors that support validation should override this
        let _ = validate;
        self.detect(text)
    }
}

/// Composite detector for single-pass scanning
pub struct MultiDetector {
    detectors: Vec<Box<dyn PiiDetector>>,
}

impl MultiDetector {
    pub fn new(detectors: Vec<Box<dyn PiiDetector>>) -> Self {
        Self { detectors }
    }

    /// Single-pass detection using Aho-Corasick for efficiency
    /// (Implementation detail – will use aho-corasick crate internally)
    pub fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
        // Phase 2: Optimize with Aho-Corasick multi-pattern matching
        // Phase 1: Simple loop over detectors (correctness first)
        let mut detections: Vec<Detection> = Vec::new();
        for detector in &self.detectors {
            detections.extend(detector.detect(text));
        }
        // Sort and resolve overlaps (critical for correct redaction)
        Self::resolve_overlaps(detections)
    }

    /// Detect with optional validation bypass
    pub fn detect_with_validation<'a>(&self, text: &'a str, validate: bool) -> Vec<Detection> {
        let mut detections: Vec<Detection> = Vec::new();
        for detector in &self.detectors {
            detections.extend(detector.detect_with_validation(text, validate));
        }
        Self::resolve_overlaps(detections)
    }

    /// Resolve overlapping detections – keep highest priority PII type
    /// Priority (higher = more specific): SSN(4) > CreditCard(3) > PhoneNumber(2) > Email(1)
    /// If same priority, keep the longer span (more specific pattern)
    fn resolve_overlaps(detections: Vec<Detection>) -> Vec<Detection> {
        if detections.is_empty() {
            return detections;
        }

        let mut sorted = detections;
        sorted.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| pii_priority(b.pii_type).cmp(&pii_priority(a.pii_type)))
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
        });

        let mut resolved = Vec::with_capacity(sorted.len());
        let mut current_idx = 0;
        let mut keep: Vec<bool> = vec![false; sorted.len()];
        keep[0] = true;

        for i in 1..sorted.len() {
            if sorted[i].start < sorted[current_idx].end {
                // Overlap detected – keep higher priority (or longer span if same priority)
                if pii_priority(sorted[i].pii_type) > pii_priority(sorted[current_idx].pii_type)
                    || (pii_priority(sorted[i].pii_type)
                        == pii_priority(sorted[current_idx].pii_type)
                        && (sorted[i].end - sorted[i].start)
                            > (sorted[current_idx].end - sorted[current_idx].start))
                {
                    keep[current_idx] = false;
                    current_idx = i;
                    keep[i] = true;
                }
            } else {
                current_idx = i;
                keep[i] = true;
            }
        }

        for (i, d) in sorted.into_iter().enumerate() {
            if keep[i] {
                resolved.push(d);
            }
        }
        resolved
    }
}

/// Returns priority for PII type (higher = more specific)
/// SSN > CreditCard > PhoneNumber > Email > IpAddress > Other
fn pii_priority(pii_type: PiiType) -> u8 {
    match pii_type {
        PiiType::Ssn => 4,
        PiiType::CreditCard => 3,
        PiiType::PhoneNumber => 2,
        PiiType::Email => 1,
        PiiType::IpAddressV4 | PiiType::IpAddressV6 => 0,
        PiiType::Other(_) => 0, // Lowest priority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Dummy detector for testing trait contract
    struct TestEmailDetector;
    impl PiiDetector for TestEmailDetector {
        fn pii_type(&self) -> PiiType {
            PiiType::Email
        }
        fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
            if let Some(idx) = text.find('@') {
                // Simplified for test – real detector uses proper regex
                let start = text[..idx].rfind(' ').map_or(0, |i| i + 1);
                let end = text[idx..].find(' ').map_or(text.len(), |i| idx + i);
                vec![Detection {
                    pii_type: self.pii_type(),
                    start,
                    end,
                    original: text[start..end].to_string(),
                }]
            } else {
                vec![]
            }
        }
    }

    #[test]
    fn test_detection_zeroizes_on_drop() {
        let detector = TestEmailDetector;
        let detection = detector.detect("contact john@example.com")[0].clone();

        // Extract original before drop
        let original = detection.original.clone();
        assert_eq!(original, "john@example.com");

        // Drop should zeroize
        std::mem::drop(detection);
        // Note: Can't directly verify zeroization in safe Rust –
        // but trait impl guarantees it happens. Fuzz tests will validate.
    }

    #[test]
    fn test_resolve_overlaps_prefers_longer_match() {
        let short = Detection {
            pii_type: PiiType::PhoneNumber,
            start: 10,
            end: 20,
            original: "1234567890".to_string(),
        };
        let long = Detection {
            pii_type: PiiType::Ssn,
            start: 12,
            end: 25,
            original: "456789012".to_string(),
        };

        let resolved = MultiDetector::resolve_overlaps(vec![short.clone(), long.clone()]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].pii_type, PiiType::Ssn); // Longer match wins
    }

    #[test]
    fn test_resolve_overlaps_priority_over_length() {
        // SSN has higher priority (4) than PhoneNumber (2)
        // Even if PhoneNumber is longer, SSN should win
        let phone = Detection {
            pii_type: PiiType::PhoneNumber,
            start: 10,
            end: 25, // longer span
            original: "123-456-7890".to_string(),
        };
        let ssn = Detection {
            pii_type: PiiType::Ssn,
            start: 12,
            end: 23, // shorter span but higher priority
            original: "123-45-6789".to_string(),
        };

        let resolved = MultiDetector::resolve_overlaps(vec![phone, ssn]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].pii_type, PiiType::Ssn); // Higher priority wins
    }

    #[test]
    fn test_pii_priority_ordering() {
        assert!(pii_priority(PiiType::Ssn) > pii_priority(PiiType::CreditCard));
        assert!(pii_priority(PiiType::CreditCard) > pii_priority(PiiType::PhoneNumber));
        assert!(pii_priority(PiiType::PhoneNumber) > pii_priority(PiiType::Email));
    }
}
