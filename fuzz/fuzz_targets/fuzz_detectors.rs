#![no_main]

use libfuzzer_sys::fuzz_target;

use auvura_core::detectors::credit_card::CreditCardDetector;
use auvura_core::detectors::email::EmailDetector;
use auvura_core::detectors::ip::{Ipv4Detector, Ipv6Detector};
use auvura_core::detectors::phone_number::PhoneNumberDetector;
use auvura_core::detectors::ssn::SSNDetector;
use auvura_core::detector::PiiDetector;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let detectors: Vec<Box<dyn PiiDetector>> = vec![
            Box::new(EmailDetector::new()),
            Box::new(PhoneNumberDetector::new()),
            Box::new(SSNDetector::new()),
            Box::new(CreditCardDetector::new()),
            Box::new(Ipv4Detector::new()),
            Box::new(Ipv6Detector::new()),
        ];

        for detector in &detectors {
            // Must not panic
            let detections = detector.detect(text);

            // All detections must have valid boundaries
            for d in &detections {
                assert!(d.start <= d.end, "detection start > end");
                assert!(d.end <= text.len(), "detection end beyond text length");
                assert!(
                    text.get(d.start..d.end).is_some(),
                    "detection boundaries are not valid UTF-8"
                );
            }

            // Detections must be sorted by start position
            for window in detections.windows(2) {
                assert!(
                    window[0].start <= window[1].start,
                    "detections not sorted by start position"
                );
            }
        }
    }
});
