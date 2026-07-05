//! Integration tests for policy serialization round-trips.
//!
//! Tests creating policies, serializing to config, and restoring from config.

use auvura_core::policy::{RedactionPolicy, RedactionPolicyConfig};
use auvura_core::types::PiiType;

#[test]
fn round_trip_default_policy() {
    let policy = RedactionPolicy::default();
    let config = policy.serialize();
    let restored = RedactionPolicy::from_config(&config);

    // Both should enable the same types
    for pii_type in [
        PiiType::Email,
        PiiType::PhoneNumber,
        PiiType::Ssn,
        PiiType::CreditCard,
        PiiType::IpAddressV4,
        PiiType::IpAddressV6,
    ] {
        assert_eq!(policy.is_enabled(pii_type), restored.is_enabled(pii_type));
    }
    assert_eq!(policy.requires_validation(), restored.requires_validation());
}

#[test]
fn round_trip_gdpr_policy() {
    let policy = RedactionPolicy::gdpr();
    let config = policy.serialize();
    let restored = RedactionPolicy::from_config(&config);

    assert!(restored.is_enabled(PiiType::Email));
    assert!(restored.is_enabled(PiiType::PhoneNumber));
    assert!(!restored.is_enabled(PiiType::Ssn));
    assert!(restored.is_enabled(PiiType::IpAddressV4));
    assert!(restored.is_enabled(PiiType::IpAddressV6));
}

#[test]
fn round_trip_hipaa_policy() {
    let policy = RedactionPolicy::hipaa();
    let config = policy.serialize();
    let restored = RedactionPolicy::from_config(&config);

    // HIPAA starts from default (all types enabled), adds allowlist
    // So all types should still be enabled after round-trip
    assert!(restored.is_enabled(PiiType::Email));
    assert!(restored.is_enabled(PiiType::PhoneNumber));
    assert!(restored.is_enabled(PiiType::Ssn));
    assert!(restored.is_enabled(PiiType::CreditCard));
    assert!(restored.is_enabled(PiiType::IpAddressV4));
    assert!(restored.is_enabled(PiiType::IpAddressV6));
    assert_eq!(
        restored.allowlist_terms(),
        &["hospital", "clinic", "medical center"]
    );
}

#[test]
fn round_trip_pci_dss_policy() {
    let policy = RedactionPolicy::pci_dss();
    let config = policy.serialize();
    let restored = RedactionPolicy::from_config(&config);

    // PCI-DSS starts from default (all types enabled), adds strict validation
    assert!(restored.is_enabled(PiiType::Email));
    assert!(restored.is_enabled(PiiType::PhoneNumber));
    assert!(restored.is_enabled(PiiType::Ssn));
    assert!(restored.is_enabled(PiiType::CreditCard));
    assert!(restored.is_enabled(PiiType::IpAddressV4));
    assert!(restored.is_enabled(PiiType::IpAddressV6));
    assert!(restored.requires_validation());
}

#[test]
fn round_trip_custom_policy() {
    let policy = RedactionPolicy::builder()
        .enable(PiiType::Email)
        .disable(PiiType::Ssn)
        .disable(PiiType::PhoneNumber)
        .with_placeholder(PiiType::Email, "[EMAIL]")
        .with_allowlist(vec!["Apple", "Google"])
        .with_blocklist(vec!["SECRET", "CONFIDENTIAL"])
        .strict_validation(false)
        .build();

    let config = policy.serialize();
    let json = serde_json::to_string_pretty(&config).unwrap();
    let restored_config: RedactionPolicyConfig = serde_json::from_str(&json).unwrap();
    let restored = RedactionPolicy::from_config(&restored_config);

    assert!(restored.is_enabled(PiiType::Email));
    assert!(!restored.is_enabled(PiiType::Ssn));
    assert!(!restored.is_enabled(PiiType::PhoneNumber));
    assert_eq!(restored.custom_placeholder(PiiType::Email), Some("[EMAIL]"));
    assert_eq!(restored.allowlist_terms(), &["Apple", "Google"]);
    assert_eq!(restored.blocklist_terms(), &["SECRET", "CONFIDENTIAL"]);
    assert!(!restored.requires_validation());
}

#[test]
fn config_json_round_trip() {
    let policy = RedactionPolicy::builder()
        .disable(PiiType::Ssn)
        .with_blocklist(vec!["TOP", "SECRET"])
        .build();

    let config = policy.serialize();
    let json = serde_json::to_string(&config).unwrap();
    let restored_config: RedactionPolicyConfig = serde_json::from_str(&json).unwrap();
    let restored = RedactionPolicy::from_config(&restored_config);

    assert!(!restored.is_enabled(PiiType::Ssn));
    assert_eq!(restored.blocklist_terms(), &["TOP", "SECRET"]);
}

#[test]
fn config_toml_round_trip() {
    let policy = RedactionPolicy::builder()
        .enable(PiiType::Email)
        .disable(PiiType::CreditCard)
        .with_placeholder(PiiType::Email, "REDACTED")
        .build();

    let config = policy.serialize();
    let toml_str = toml::to_string(&config).unwrap();
    let restored_config: RedactionPolicyConfig = toml::from_str(&toml_str).unwrap();
    let restored = RedactionPolicy::from_config(&restored_config);

    assert!(restored.is_enabled(PiiType::Email));
    assert!(!restored.is_enabled(PiiType::CreditCard));
    assert_eq!(
        restored.custom_placeholder(PiiType::Email),
        Some("REDACTED")
    );
}

fn default_config() -> RedactionPolicyConfig {
    serde_json::from_str("{}").unwrap()
}

#[test]
fn empty_config_enables_no_types() {
    let config = default_config();
    let policy = RedactionPolicy::from_config(&config);

    // Empty config means no types in enabled_types, so nothing is enabled
    for pii_type in [
        PiiType::Email,
        PiiType::PhoneNumber,
        PiiType::Ssn,
        PiiType::CreditCard,
        PiiType::IpAddressV4,
        PiiType::IpAddressV6,
    ] {
        assert!(
            !policy.is_enabled(pii_type),
            "{:?} should not be enabled in empty config",
            pii_type
        );
    }
}

#[test]
fn serializable_to_json_schema() {
    let policy = RedactionPolicy::gdpr();
    let config = policy.serialize();
    let json = serde_json::to_string_pretty(&config).unwrap();

    // Verify the JSON has expected fields
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.get("enabled_types").is_some());
    assert!(parsed.get("placeholders").is_some());
    assert!(parsed.get("allowlist").is_some());
    assert!(parsed.get("blocklist").is_some());
    assert!(parsed.get("strict_validation").is_some());
}

#[test]
fn policy_functionality_preserved_after_round_trip() {
    let detectors: Vec<Box<dyn auvura_core::detector::PiiDetector>> = vec![
        Box::new(auvura_core::detectors::email::EmailDetector::new()),
        Box::new(auvura_core::detectors::ssn::SSNDetector::new()),
    ];

    let policy = RedactionPolicy::builder().disable(PiiType::Ssn).build();
    let config = policy.serialize();
    let restored = RedactionPolicy::from_config(&config);

    let redactor_original = auvura_core::redactor::Redactor::new(
        detectors
            .iter()
            .map(|_d| {
                Box::new(auvura_core::detectors::email::EmailDetector::new())
                    as Box<dyn auvura_core::detector::PiiDetector>
            })
            .collect(),
        policy,
    );

    let redactor_restored = auvura_core::redactor::Redactor::new(
        detectors
            .iter()
            .map(|_d| {
                Box::new(auvura_core::detectors::email::EmailDetector::new())
                    as Box<dyn auvura_core::detector::PiiDetector>
            })
            .collect(),
        restored,
    );

    let input = "Email john@example.com, SSN 123-45-6789";
    let result_original = redactor_original.redact(input);
    let result_restored = redactor_restored.redact(input);

    // Both should behave identically: email redacted, SSN preserved
    assert_eq!(result_original, result_restored);
    assert!(!result_original.contains("john@example.com"));
    assert!(result_original.contains("123-45-6789"));
}
