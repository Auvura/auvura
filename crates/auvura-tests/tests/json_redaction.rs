//! Integration tests for JSON-structure-aware redaction.
//!
//! Tests the full flow: JSON parsing → recursive value redaction → structure preservation.

use auvura_core::detector::PiiDetector;
use auvura_core::detectors::credit_card::CreditCardDetector;
use auvura_core::detectors::email::EmailDetector;
use auvura_core::detectors::ip::{Ipv4Detector, Ipv6Detector};
use auvura_core::detectors::phone_number::PhoneNumberDetector;
use auvura_core::detectors::ssn::SSNDetector;
use auvura_core::json::JsonRedactor;
use auvura_core::policy::RedactionPolicy;
use auvura_core::redactor::Redactor;
use serde_json::Value;

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

fn json_redactor() -> JsonRedactor {
    JsonRedactor::new(full_redactor())
}

#[test]
fn redacts_email_in_json_value() {
    let jr = json_redactor();
    let input = r#"{"message": "Contact john@example.com"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    let msg = parsed["message"].as_str().unwrap();
    assert!(!msg.contains("john@example.com"));
    assert!(msg.contains("@"));
}

#[test]
fn preserves_json_keys() {
    let jr = json_redactor();
    let input = r#"{"email": "john@example.com", "name": "John"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert!(parsed.get("email").is_some());
    assert!(parsed.get("name").is_some());
}

#[test]
fn numbers_unchanged() {
    let jr = json_redactor();
    let input = r#"{"count": 42, "price": 19.99, "active": true, "data": null}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["count"], 42);
    assert_eq!(parsed["price"], 19.99);
    assert_eq!(parsed["active"], true);
    assert_eq!(parsed["data"], Value::Null);
}

#[test]
fn nested_objects_redacted() {
    let jr = json_redactor();
    let input = r#"{"user": {"contact": {"email": "jane@example.com"}, "age": 30}}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    let email = parsed["user"]["contact"]["email"].as_str().unwrap();
    assert!(!email.contains("jane@example.com"));
    assert_eq!(parsed["user"]["age"], 30);
}

#[test]
fn arrays_of_strings_redacted() {
    let jr = json_redactor();
    let input = r#"{"emails": ["alice@co.com", "bob@co.com"]}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    let emails = parsed["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 2);
    for email in emails {
        let s = email.as_str().unwrap();
        assert!(!s.contains("alice@co.com"));
        assert!(!s.contains("bob@co.com"));
    }
}

#[test]
fn arrays_of_objects_redacted() {
    let jr = json_redactor();
    let input = r#"{"users": [{"email": "a@b.com"}, {"email": "c@d.com"}]}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    let users = parsed["users"].as_array().unwrap();
    for user in users {
        let email = user["email"].as_str().unwrap();
        assert!(!email.contains("@b.com"));
        assert!(!email.contains("@d.com"));
    }
}

#[test]
fn ssn_in_json() {
    let jr = json_redactor();
    let input = r#"{"ssn": "123-45-6789"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["ssn"].as_str().unwrap(), "███-██-████");
}

#[test]
fn credit_card_in_json() {
    let jr = json_redactor();
    let input = r#"{"card": "4111 1111 1111 1111"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["card"].as_str().unwrap(), "████ ████ ████ 1111");
}

#[test]
fn ip_address_in_json() {
    let jr = json_redactor();
    let input = r#"{"ip": "192.168.1.1"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    let ip = parsed["ip"].as_str().unwrap();
    assert!(!ip.contains("192"));
    assert!(!ip.contains("168"));
}

#[test]
fn phone_in_json() {
    let jr = json_redactor();
    let input = r#"{"phone": "+12025550123"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    let phone = parsed["phone"].as_str().unwrap();
    assert!(!phone.contains("202555"));
    assert!(phone.contains("+"));
}

#[test]
fn mixed_pii_types() {
    let jr = json_redactor();
    let input = r#"{"email": "x@y.com", "ssn": "111-22-3333", "card": "4111 1111 1111 1111", "safe": "hello"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert!(!parsed["email"].as_str().unwrap().contains("x@y.com"));
    assert_eq!(parsed["ssn"].as_str().unwrap(), "███-██-████");
    assert_eq!(parsed["card"].as_str().unwrap(), "████ ████ ████ 1111");
    assert_eq!(parsed["safe"].as_str().unwrap(), "hello");
}

#[test]
fn invalid_json_returns_error() {
    let jr = json_redactor();
    assert!(jr.redact_json(r#"{"broken": "#).is_err());
}

#[test]
fn empty_json_object() {
    let jr = json_redactor();
    let result = jr.redact_json("{}").unwrap();
    assert_eq!(result, "{}");
}

#[test]
fn empty_json_array() {
    let jr = json_redactor();
    let result = jr.redact_json("[]").unwrap();
    assert_eq!(result, "[]");
}

#[test]
fn deeply_nested_json() {
    let jr = json_redactor();
    let input = r#"{"a": {"b": {"c": {"d": {"e": "user@domain.com"}}}}}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    let email = parsed["a"]["b"]["c"]["d"]["e"].as_str().unwrap();
    assert!(!email.contains("user@domain.com"));
}

#[test]
fn pretty_print_output() {
    let jr = json_redactor();
    let input = r#"{"email":"john@example.com"}"#;
    let result = jr.redact_json_pretty(input).unwrap();
    assert!(result.contains('\n'));
    assert!(result.contains("  "));
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert!(!parsed["email"]
        .as_str()
        .unwrap()
        .contains("john@example.com"));
}

#[test]
fn redact_value_in_place() {
    let jr = json_redactor();
    let mut value: Value = serde_json::from_str(r#"{"email": "a@b.com"}"#).unwrap();
    jr.redact_value(&mut value);
    assert!(!value["email"].as_str().unwrap().contains("a@b.com"));
}

#[test]
fn json_string_with_special_characters() {
    let jr = json_redactor();
    let input = r#"{"msg": "Hello\nWorld\tTab"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["msg"].as_str().unwrap(), "Hello\nWorld\tTab");
}

#[test]
fn json_with_escaped_quotes() {
    let jr = json_redactor();
    let input = r#"{"msg": "He said \"email me at test@example.com\""}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert!(!parsed["msg"].as_str().unwrap().contains("test@example.com"));
}

#[test]
fn json_unicode_values() {
    let jr = json_redactor();
    let input = r#"{"greeting": "こんにちは", "email": "x@y.com"}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["greeting"].as_str().unwrap(), "こんにちは");
    assert!(!parsed["email"].as_str().unwrap().contains("x@y.com"));
}

#[test]
fn json_preserves_number_types() {
    let jr = json_redactor();
    let input = r#"{"int": 42, "float": 2.71, "neg": -1, "sci": 1e10}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["int"], 42);
    assert_eq!(parsed["float"], 2.71);
    assert_eq!(parsed["neg"], -1);
    assert_eq!(parsed["sci"], 1e10);
}

#[test]
fn json_null_values_preserved() {
    let jr = json_redactor();
    let input = r#"{"a": null, "b": "text", "c": null}"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["a"], Value::Null);
    assert_eq!(parsed["c"], Value::Null);
}

#[test]
fn json_array_mixed_types() {
    let jr = json_redactor();
    let input = r#"[1, "text", true, null, 2.71, {"key": "value"}]"#;
    let result = jr.redact_json(input).unwrap();
    let parsed: Value = serde_json::from_str(&result).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr[0], 1);
    assert_eq!(arr[1], "text");
    assert_eq!(arr[2], true);
    assert_eq!(arr[3], Value::Null);
    assert_eq!(arr[4], 2.71);
    assert_eq!(arr[5]["key"], "value");
}
