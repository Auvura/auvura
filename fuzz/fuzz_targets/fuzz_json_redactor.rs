#![no_main]

use libfuzzer_sys::fuzz_target;

use auvura_core::detectors::credit_card::CreditCardDetector;
use auvura_core::detectors::email::EmailDetector;
use auvura_core::detectors::ip::{Ipv4Detector, Ipv6Detector};
use auvura_core::detectors::phone_number::PhoneNumberDetector;
use auvura_core::detectors::ssn::SSNDetector;
use auvura_core::detector::PiiDetector;
use auvura_core::json::JsonRedactor;
use auvura_core::policy::RedactionPolicy;
use auvura_core::redactor::Redactor;

fn build_json_redactor() -> JsonRedactor {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![
        Box::new(EmailDetector::new()),
        Box::new(PhoneNumberDetector::new()),
        Box::new(SSNDetector::new()),
        Box::new(CreditCardDetector::new()),
        Box::new(Ipv4Detector::new()),
        Box::new(Ipv6Detector::new()),
    ];
    JsonRedactor::new(Redactor::new(detectors, RedactionPolicy::default()))
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let jr = build_json_redactor();

        // redact_json must not panic on any input
        if let Ok(result) = jr.redact_json(text) {
            // Result should be valid JSON
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&result);
            assert!(parsed.is_ok(), "redact_json produced invalid JSON: {}", result);
        }

        // redact_json_pretty must not panic on any input
        if let Ok(result) = jr.redact_json_pretty(text) {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&result);
            assert!(
                parsed.is_ok(),
                "redact_json_pretty produced invalid JSON: {}",
                result
            );
        }
    }
});
