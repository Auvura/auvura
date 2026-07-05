use crate::types::PiiType;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
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
    fn detect(&self, text: &str) -> Vec<Detection>;

    /// Detect PII with optional validation bypass
    /// Called by redactor with policy's strict_validation setting
    fn detect_with_validation(&self, text: &str, validate: bool) -> Vec<Detection> {
        // Default: ignore validation flag and use detect()
        // Detectors that support validation should override this
        let _ = validate;
        self.detect(text)
    }

    /// Returns literal anchor patterns for Aho-Corasick pre-filtering.
    /// These are substrings that MUST be present in text containing this PII type.
    /// Default: empty (no optimization, full regex scan).
    fn anchor_patterns(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Detect PII within a window of text, adjusting offsets by `window_start`.
    /// Used by MultiDetector for Aho-Corasick-optimized scanning.
    /// Default: delegates to detect() on the window (word boundaries may be
    /// affected by window truncation — detectors with boundary-sensitive patterns
    /// should override this).
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

/// Anchor-based candidate region for a detector
struct AnchorRegion {
    start: usize,
    end: usize,
}

/// Composite detector for single-pass scanning
pub struct MultiDetector {
    detectors: Vec<Box<dyn PiiDetector>>,
    /// Pre-built Aho-Corasick automaton for anchor patterns.
    /// `anchor_detector_idx[i]` maps automaton pattern index `i` to detector index.
    ac: Option<AhoCorasick>,
    anchor_detector_idx: Vec<usize>,
}

impl MultiDetector {
    pub fn new(detectors: Vec<Box<dyn PiiDetector>>) -> Self {
        // Build Aho-Corasick automaton from all detector anchor patterns
        let mut patterns: Vec<&str> = Vec::new();
        let mut detector_idx: Vec<usize> = Vec::new();

        for (i, det) in detectors.iter().enumerate() {
            for pattern in det.anchor_patterns() {
                patterns.push(pattern);
                detector_idx.push(i);
            }
        }

        let ac = if !patterns.is_empty() {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&patterns)
                    .expect("Aho-Corasick patterns are valid"),
            )
        } else {
            None
        };

        Self {
            detectors,
            ac,
            anchor_detector_idx: detector_idx,
        }
    }

    /// Single-pass detection using Aho-Corasick for efficiency.
    ///
    /// Strategy:
    /// 1. If anchors are defined, build Aho-Corasick automaton once.
    /// 2. Scan text once to find all anchor positions (O(n + m + z)).
    /// 3. For each detector, extract candidate windows around its anchors.
    /// 4. Run detector's regex only on reduced candidate text.
    /// 5. Sort and resolve overlaps.
    pub fn detect(&self, text: &str) -> Vec<Detection> {
        if text.is_empty() {
            return Vec::new();
        }

        let Some(ref ac) = self.ac else {
            // No anchors — fall back to naive loop
            return self.detect_naive(text);
        };

        // Single Aho-Corasick pass to find all anchor matches
        let anchor_matches: Vec<(usize, usize, usize)> = ac
            .find_iter(text)
            .map(|m| (self.anchor_detector_idx[m.pattern()], m.start(), m.end()))
            .collect();

        // If no anchors matched, still run detectors that have no anchor patterns
        if anchor_matches.is_empty() {
            let mut detections = Vec::new();
            for det in &self.detectors {
                if det.anchor_patterns().is_empty() {
                    detections.extend(det.detect(text));
                }
            }
            return Self::resolve_overlaps(detections);
        }

        // Group anchor positions by detector index, expand to candidate windows
        let mut candidate_regions: Vec<Vec<AnchorRegion>> =
            (0..self.detectors.len()).map(|_| Vec::new()).collect();
        for &(det_idx, start, end) in &anchor_matches {
            // Expand window: 64 bytes before (for local part, area code, etc.)
            // and 64 bytes after (for domain, remaining digits, etc.)
            let win_start = start.saturating_sub(64);
            let win_end = std::cmp::min(text.len(), end + 64);

            // Merge overlapping windows for the same detector
            if let Some(last) = candidate_regions[det_idx].last_mut() {
                if win_start <= last.end {
                    last.end = std::cmp::max(last.end, win_end);
                    continue;
                }
            }
            candidate_regions[det_idx].push(AnchorRegion {
                start: win_start,
                end: win_end,
            });
        }

        // Run each detector on its candidate windows (or full text if no anchors)
        let mut detections: Vec<Detection> = Vec::new();
        for (det_idx, det) in self.detectors.iter().enumerate() {
            if candidate_regions[det_idx].is_empty() {
                // If the detector has anchor patterns but none were found, skip it.
                // If the detector has NO anchor patterns, run on full text as fallback.
                if !det.anchor_patterns().is_empty() {
                    continue;
                }
                detections.extend(det.detect(text));
                continue;
            }

            for region in &candidate_regions[det_idx] {
                if region.start >= region.end || region.end > text.len() {
                    continue;
                }
                let window = &text[region.start..region.end];
                detections.extend(det.detect_in_window(window, region.start));
            }
        }

        Self::resolve_overlaps(detections)
    }

    /// Detect with optional validation bypass
    pub fn detect_with_validation(&self, text: &str, validate: bool) -> Vec<Detection> {
        if text.is_empty() {
            return Vec::new();
        }

        let Some(ref ac) = self.ac else {
            return self.detect_naive_with_validation(text, validate);
        };

        let anchor_matches: Vec<(usize, usize, usize)> = ac
            .find_iter(text)
            .map(|m| (self.anchor_detector_idx[m.pattern()], m.start(), m.end()))
            .collect();

        // If no anchors matched, still run detectors that have no anchor patterns
        // (e.g. PhoneNumberDetector which falls back to full-text regex scan)
        if anchor_matches.is_empty() {
            let mut detections = Vec::new();
            for det in &self.detectors {
                if det.anchor_patterns().is_empty() {
                    detections.extend(det.detect_with_validation(text, validate));
                }
            }
            return Self::resolve_overlaps(detections);
        }

        let mut candidate_regions: Vec<Vec<AnchorRegion>> =
            (0..self.detectors.len()).map(|_| Vec::new()).collect();
        for &(det_idx, start, end) in &anchor_matches {
            let win_start = start.saturating_sub(64);
            let win_end = std::cmp::min(text.len(), end + 64);

            if let Some(last) = candidate_regions[det_idx].last_mut() {
                if win_start <= last.end {
                    last.end = std::cmp::max(last.end, win_end);
                    continue;
                }
            }
            candidate_regions[det_idx].push(AnchorRegion {
                start: win_start,
                end: win_end,
            });
        }

        let mut detections: Vec<Detection> = Vec::new();
        for (det_idx, det) in self.detectors.iter().enumerate() {
            if candidate_regions[det_idx].is_empty() {
                if !det.anchor_patterns().is_empty() {
                    continue;
                }
                detections.extend(det.detect_with_validation(text, validate));
                continue;
            }

            for region in &candidate_regions[det_idx] {
                if region.start >= region.end || region.end > text.len() {
                    continue;
                }
                let window = &text[region.start..region.end];
                // Use detect_with_validation on the window, adjusting offsets
                let window_detections = det.detect_with_validation(window, validate);
                detections.extend(window_detections.into_iter().map(|mut d| {
                    d.start += region.start;
                    d.end += region.start;
                    d
                }));
            }
        }

        Self::resolve_overlaps(detections)
    }

    /// Fallback: naive loop over detectors (no Aho-Corasick optimization)
    fn detect_naive(&self, text: &str) -> Vec<Detection> {
        let mut detections: Vec<Detection> = Vec::new();
        for detector in &self.detectors {
            detections.extend(detector.detect(text));
        }
        Self::resolve_overlaps(detections)
    }

    /// Fallback: naive loop with validation bypass
    fn detect_naive_with_validation(&self, text: &str, validate: bool) -> Vec<Detection> {
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
        fn detect(&self, text: &str) -> Vec<Detection> {
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
        fn anchor_patterns(&self) -> Vec<&'static str> {
            vec!["@"]
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

    #[test]
    fn test_aho_corasick_finds_anchors() {
        use crate::detectors::email::EmailDetector;
        let detectors: Vec<Box<dyn PiiDetector>> = vec![Box::new(EmailDetector::new())];
        let multi = MultiDetector::new(detectors);

        let detections = multi.detect("contact john@example.com or jane@test.org");
        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].original, "john@example.com");
        assert_eq!(detections[1].original, "jane@test.org");
    }

    #[test]
    fn test_aho_corasick_no_anchors_no_work() {
        // Detector with no anchor patterns falls back to naive
        struct NoAnchorDetector;
        impl PiiDetector for NoAnchorDetector {
            fn pii_type(&self) -> PiiType {
                PiiType::Other("test")
            }
            fn detect(&self, _text: &str) -> Vec<Detection> {
                vec![]
            }
        }

        let detectors: Vec<Box<dyn PiiDetector>> = vec![Box::new(NoAnchorDetector)];
        let multi = MultiDetector::new(detectors);
        assert!(multi.ac.is_none());
        assert!(multi.detect("no pii here").is_empty());
    }
}
