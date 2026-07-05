//! End-to-end integration tests for the PII detection and redaction pipeline.
//!
//! Tests the full flow: detector creation → policy configuration → redaction → verification.

use auvura_core::detector::PiiDetector;
use auvura_core::detectors::credit_card::CreditCardDetector;
use auvura_core::detectors::email::EmailDetector;
use auvura_core::detectors::ip::{Ipv4Detector, Ipv6Detector};
use auvura_core::detectors::phone_number::PhoneNumberDetector;
use auvura_core::detectors::ssn::SSNDetector;
use auvura_core::policy::RedactionPolicy;
use auvura_core::redactor::Redactor;
use auvura_core::types::PiiType;

/// Build a full-featured redactor with all detectors enabled.
fn full_redactor() -> Redactor {
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

#[test]
fn redacts_email_address() {
    let redactor = full_redactor();
    let input = "Send docs to john.doe@example.com";
    let result = redactor.redact(input);
    assert!(!result.contains("john.doe@example.com"));
    assert!(result.contains("@"));
    assert!(result.contains(".com"));
}

#[test]
fn redacts_phone_number() {
    let redactor = full_redactor();
    let input = "Call me at +12025550123 or (202) 555-0124";
    let result = redactor.redact(input);
    assert!(!result.contains("2025550123"));
    assert!(!result.contains("555-0124"));
}

#[test]
fn redacts_ssn() {
    let redactor = full_redactor();
    let input = "My SSN is 123-45-6789";
    let result = redactor.redact(input);
    assert_eq!(result, "My SSN is ███-██-████");
}

#[test]
fn redacts_credit_card() {
    let redactor = full_redactor();
    let input = "Card: 4111 1111 1111 1111";
    let result = redactor.redact(input);
    assert_eq!(result, "Card: ████ ████ ████ 1111");
}

#[test]
fn redacts_ipv4_address() {
    let redactor = full_redactor();
    let input = "Server at 192.168.1.100";
    let result = redactor.redact(input);
    assert!(!result.contains("192.168.1.100"));
}

#[test]
fn redacts_ipv6_address() {
    let redactor = full_redactor();
    let input = "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    let result = redactor.redact(input);
    assert!(!result.contains("2001:0db8"));
}

#[test]
fn redacts_multiple_pii_types_in_one_text() {
    let redactor = full_redactor();
    let input = "Name: john@example.com, SSN: 987-65-4321, Card: 4111 1111 1111 1111";
    let result = redactor.redact(input);
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("987-65-4321"));
    assert!(!result.contains("4111 1111 1111 1111"));
}

#[test]
fn no_pii_returns_original() {
    let redactor = full_redactor();
    let input = "This is a normal sentence with no PII.";
    let result = redactor.redact(input);
    assert_eq!(result, input);
}

#[test]
fn empty_string_handled() {
    let redactor = full_redactor();
    let result = redactor.redact("");
    assert_eq!(result, "");
}

#[test]
fn unicode_text_with_pii() {
    let redactor = full_redactor();
    let input = "联系邮箱: john@example.com です";
    let result = redactor.redact(input);
    assert!(!result.contains("john@example.com"));
    assert!(result.contains("联系邮箱:"));
    assert!(result.contains("です"));
}

#[test]
fn policy_disables_specific_type() {
    let detectors: Vec<Box<dyn PiiDetector>> =
        vec![Box::new(EmailDetector::new()), Box::new(SSNDetector::new())];
    let policy = RedactionPolicy::builder().disable(PiiType::Ssn).build();
    let redactor = Redactor::new(detectors, policy);

    let input = "Email john@example.com, SSN 123-45-6789";
    let result = redactor.redact(input);
    assert!(!result.contains("john@example.com"));
    assert!(result.contains("123-45-6789")); // SSN NOT redacted
}

#[test]
fn custom_placeholder_overrides() {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![Box::new(EmailDetector::new())];
    let policy = RedactionPolicy::builder()
        .with_placeholder(PiiType::Email, "[REDACTED_EMAIL]")
        .build();
    let redactor = Redactor::new(detectors, policy);

    let input = "Contact john@example.com";
    let result = redactor.redact(input);
    assert_eq!(result, "Contact [REDACTED_EMAIL]");
}

#[test]
fn allowlist_prevents_redaction() {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![Box::new(EmailDetector::new())];
    let policy = RedactionPolicy::builder()
        .with_allowlist(vec!["support@example.com"])
        .build();
    let redactor = Redactor::new(detectors, policy);

    let input = "Email support@example.com or john@example.com";
    let result = redactor.redact(input);
    assert!(result.contains("support@example.com"));
    assert!(!result.contains("john@example.com"));
}

#[test]
fn blocklist_forces_redaction() {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![];
    let policy = RedactionPolicy::builder()
        .with_blocklist(vec!["CONFIDENTIAL"])
        .build();
    let redactor = Redactor::new(detectors, policy);

    let input = "This is CONFIDENTIAL information";
    let result = redactor.redact(input);
    assert!(!result.contains("CONFIDENTIAL"));
}

#[test]
fn gdpr_profile_excludes_ssn() {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![
        Box::new(EmailDetector::new()),
        Box::new(PhoneNumberDetector::new()),
        Box::new(SSNDetector::new()),
    ];
    let policy = RedactionPolicy::gdpr();
    let redactor = Redactor::new(detectors, policy);

    let input = "Email john@example.com, SSN 123-45-6789";
    let result = redactor.redact(input);
    assert!(!result.contains("john@example.com"));
    assert!(result.contains("123-45-6789")); // SSN NOT redacted under GDPR
}

#[test]
fn credit_card_last_four_visible() {
    let redactor = full_redactor();
    let input = "Card: 4111 1111 1111 1111";
    let result = redactor.redact(input);
    assert!(result.contains("1111"));
    assert!(!result.contains("4111"));
}

#[test]
fn ssn_preserves_hyphens() {
    let redactor = full_redactor();
    let input = "SSN: 123-45-6789";
    let result = redactor.redact(input);
    assert!(result.contains("-"));
    assert_eq!(result, "SSN: ███-██-████");
}

#[test]
fn phone_preserves_plus_sign() {
    let redactor = full_redactor();
    let input = "Call +12025550123";
    let result = redactor.redact(input);
    assert!(result.contains("+"));
}

#[test]
fn large_text_with_pii() {
    let redactor = full_redactor();
    let mut input = String::from("Normal text. ");
    input.push_str("Email: john@example.com. ");
    for _ in 0..100 {
        input.push_str("More normal text. ");
    }
    input.push_str("SSN: 123-45-6789.");
    let result = redactor.redact(&input);
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("123-45-6789"));
    assert!(result.contains("Normal text."));
}

#[test]
fn repeated_pii_patterns() {
    let redactor = full_redactor();
    let input = "a@b.com and c@d.com and e@f.com";
    let result = redactor.redact(input);
    // All emails should be redacted
    assert!(!result.contains("a@b.com"));
    assert!(!result.contains("c@d.com"));
    assert!(!result.contains("e@f.com"));
    // But @ symbols should remain (from structured redaction)
    assert!(result.matches('@').count() >= 3);
}
