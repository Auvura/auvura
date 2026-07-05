#![no_main]

use libfuzzer_sys::fuzz_target;

use auvura_core::detectors::credit_card::CreditCardDetector;
use auvura_core::detectors::email::EmailDetector;
use auvura_core::detectors::ip::{Ipv4Detector, Ipv6Detector};
use auvura_core::detectors::phone_number::PhoneNumberDetector;
use auvura_core::detectors::ssn::SSNDetector;
use auvura_core::detector::PiiDetector;
use auvura_core::policy::RedactionPolicy;
use auvura_core::redactor::Redactor;

fn build_redactor() -> Redactor {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![
        Box::new(EmailDetector::new()),
        Box::new(PhoneNumberDetector::new()),
        Box::new(SSNDetector::new()),
        Box::new(CreditCardDetector::new()),
        Box::new(Ipv4Detector::new()),
        Box::new(Ipv6Detector::new()),
    ];
    Redactor::new(detectors, RedactionPolicy::default())
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let redactor = build_redactor();

        // Must not panic
        let _result = redactor.redact(text);

        // Redaction should produce valid UTF-8 (it always does via String)
        let result = redactor.redact(text);
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
    }
});
