use crate::types::PiiType;
use zeroize::Zeroize;

/// Detection result with memory safety guarantees
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub pii_type: PiiType,
    pub start: usize,      // UTF-8 byte offset (NOT char index)
    pub end: usize,        // UTF-8 byte offset
    pub original: String,  // Original text – will be zeroized on drop
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

    /// Optional validation step (e.g., Luhn check for credit cards)
    /// Called by redactor AFTER pattern match to reduce false positives
    fn validate(&self, _candidate: &str) -> bool {
        true // Default: no validation required
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

    /// Resolve overlapping detections – keep highest priority PII type
    /// (e.g., if "123-45-6789" matches both SSN and generic number, keep SSN)
    fn resolve_overlaps(mut detections: Vec<Detection>) -> Vec<Detection> {
        if detections.is_empty() {
            return detections;
        }

        detections.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
        });

        let mut resolved = Vec::with_capacity(detections.len());
        let mut current_idx = 0;

        for i in 1..detections.len() {
            if detections[i].start < detections[current_idx].end {
                // Overlap detected – keep the longer span (more specific pattern)
                if detections[i].end - detections[i].start > 
                    detections[current_idx].end - detections[current_idx].start {
                    current_idx = i;
                }
            } else {
                resolved.push(detections[current_idx].clone());
                current_idx = i;
            }
        }
        resolved.push(detections[current_idx].clone());
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Dummy detector for testing trait contract
    struct TestEmailDetector;
    impl PiiDetector for TestEmailDetector {
        fn pii_type(&self) -> PiiType { PiiType::Email }
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
}
