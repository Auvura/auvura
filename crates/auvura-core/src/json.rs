use crate::redactor::Redactor;
use serde_json::Value;

/// JSON-structure-aware redactor.
///
/// Parses JSON input, walks the value tree, and applies PII redaction
/// to every string value while preserving the surrounding JSON structure.
/// Keys, numbers, booleans, and nulls are left untouched.
pub struct JsonRedactor {
    redactor: Redactor,
}

impl JsonRedactor {
    /// Create a new `JsonRedactor` wrapping the given [`Redactor`].
    pub fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }

    /// Redact PII inside a JSON string.
    ///
    /// Parses the input, redacts every string value, and re-serializes.
    /// Returns the re-serialized JSON with PII redacted.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the input is not valid JSON.
    pub fn redact_json(&self, json: &str) -> Result<String, serde_json::Error> {
        let mut value: Value = serde_json::from_str(json)?;
        self.redact_value(&mut value);
        serde_json::to_string(&value)
    }

    /// Redact PII inside a JSON string, pretty-printed.
    ///
    /// Same as [`redact_json`](Self::redact_json) but outputs indented JSON.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the input is not valid JSON.
    pub fn redact_json_pretty(&self, json: &str) -> Result<String, serde_json::Error> {
        let mut value: Value = serde_json::from_str(json)?;
        self.redact_value(&mut value);
        serde_json::to_string_pretty(&value)
    }

    /// Recursively redact PII inside a [`Value`] in place.
    ///
    /// - String values are redacted via the inner [`Redactor`].
    /// - Object keys are **not** redacted (structure is preserved).
    /// - Numbers, booleans, and null are left untouched.
    /// - Arrays and nested objects are traversed recursively.
    pub fn redact_value(&self, value: &mut Value) {
        match value {
            Value::String(s) => {
                let redacted = self.redactor.redact(s);
                // Only allocate if the redactor returned an owned value
                if let std::borrow::Cow::Owned(owned) = redacted {
                    *s = owned;
                }
                // Cow::Borrowed means nothing changed — leave `s` as-is
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_value(item);
                }
            }
            Value::Object(map) => {
                for val in map.values_mut() {
                    self.redact_value(val);
                }
            }
            // Numbers, booleans, null — no-op
            _ => {}
        }
    }

    /// Consume the `JsonRedactor` and return the inner [`Redactor`].
    pub fn into_inner(self) -> Redactor {
        self.redactor
    }

    /// Borrow the inner [`Redactor`].
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::PiiDetector;
    use crate::detectors::credit_card::CreditCardDetector;
    use crate::detectors::email::EmailDetector;
    use crate::detectors::ip::{Ipv4Detector, Ipv6Detector};
    use crate::detectors::phone_number::PhoneNumberDetector;
    use crate::detectors::ssn::SSNDetector;
    use crate::policy::RedactionPolicy;

    fn test_redactor() -> Redactor {
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
    fn test_redacts_email_in_string_value() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"message": "Contact john@example.com"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let msg = parsed["message"].as_str().unwrap();
        assert!(msg.contains("@"));
        assert!(!msg.contains("john@example.com"));
    }

    #[test]
    fn test_preserves_json_keys() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"email": "john@example.com", "name": "John"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        // Key "email" is preserved
        assert!(parsed.get("email").is_some());
        // Value is redacted
        let email = parsed["email"].as_str().unwrap();
        assert!(!email.contains("john@example.com"));
    }

    #[test]
    fn test_numbers_unchanged() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"count": 42, "price": 19.99, "active": true, "data": null}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["count"], 42);
        assert_eq!(parsed["price"], 19.99);
        assert_eq!(parsed["active"], true);
        assert_eq!(parsed["data"], Value::Null);
    }

    #[test]
    fn test_nested_objects() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"user": {"contact": {"email": "jane@example.com"}, "age": 30}}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let email = parsed["user"]["contact"]["email"].as_str().unwrap();
        assert!(!email.contains("jane@example.com"));
        assert_eq!(parsed["user"]["age"], 30);
    }

    #[test]
    fn test_arrays() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"emails": ["alice@example.com", "bob@example.com"]}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let emails = parsed["emails"].as_array().unwrap();
        assert_eq!(emails.len(), 2);
        for email in emails {
            let s = email.as_str().unwrap();
            assert!(!s.contains("@example.com"));
            assert!(s.contains("@"));
        }
    }

    #[test]
    fn test_ssn_in_json() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"ssn": "123-45-6789"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let ssn = parsed["ssn"].as_str().unwrap();
        assert_eq!(ssn, "███-██-████");
    }

    #[test]
    fn test_credit_card_in_json() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"card": "4111 1111 1111 1111"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let card = parsed["card"].as_str().unwrap();
        assert_eq!(card, "████ ████ ████ 1111");
    }

    #[test]
    fn test_ip_address_in_json() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"ip": "192.168.1.1"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let ip = parsed["ip"].as_str().unwrap();
        // Format-preserving: digits replaced, dots kept
        assert_eq!(ip, "███.███.█.█");
    }

    #[test]
    fn test_phone_in_json() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"phone": "+12025550123"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let phone = parsed["phone"].as_str().unwrap();
        // Format-preserving: digits replaced, + kept
        assert_eq!(phone, "+███████████");
    }

    #[test]
    fn test_no_pii_passthrough() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"name": "Alice", "age": 25, "city": "Seattle"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["name"], "Alice");
        assert_eq!(parsed["age"], 25);
        assert_eq!(parsed["city"], "Seattle");
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"broken": "#;
        assert!(jr.redact_json(input).is_err());
    }

    #[test]
    fn test_empty_string_value() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"data": ""}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["data"], "");
    }

    #[test]
    fn test_mixed_pii_types() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"email": "test@example.com", "ssn": "123-45-6789", "card": "4111 1111 1111 1111", "safe": "hello"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        // All PII redacted
        assert!(!parsed["email"].as_str().unwrap().contains("test@"));
        assert_eq!(parsed["ssn"].as_str().unwrap(), "███-██-████");
        assert_eq!(parsed["card"].as_str().unwrap(), "████ ████ ████ 1111");
        // Safe string unchanged
        assert_eq!(parsed["safe"].as_str().unwrap(), "hello");
    }

    #[test]
    fn test_pretty_print() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"email":"john@example.com"}"#;
        let result = jr.redact_json_pretty(input).unwrap();
        assert!(result.contains('\n'));
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let email = parsed["email"].as_str().unwrap();
        assert!(!email.contains("john@example.com"));
    }

    #[test]
    fn test_into_inner() {
        let redactor = test_redactor();
        let jr = JsonRedactor::new(redactor);
        let inner = jr.into_inner();
        assert!(inner.redact("no pii") == "no pii");
    }

    #[test]
    fn test_redact_value_directly() {
        let jr = JsonRedactor::new(test_redactor());
        let mut value: Value = serde_json::from_str(r#"{"email": "x@y.com"}"#).unwrap();
        jr.redact_value(&mut value);
        let email = value["email"].as_str().unwrap();
        assert!(!email.contains("x@y.com"));
    }

    #[test]
    fn test_deeply_nested() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"a": {"b": {"c": {"d": "user@domain.com"}}}}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let email = parsed["a"]["b"]["c"]["d"].as_str().unwrap();
        assert!(!email.contains("user@domain.com"));
        assert!(email.contains("@"));
    }

    #[test]
    fn test_array_of_objects() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"users": [{"email": "a@b.com"}, {"email": "c@d.com"}]}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let users = parsed["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        for user in users {
            let email = user["email"].as_str().unwrap();
            assert!(!email.contains("@b.com"));
            assert!(!email.contains("@d.com"));
        }
    }

    #[test]
    fn test_unicode_in_json_values() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"greeting": "hello"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["greeting"], "hello");
    }

    #[test]
    fn test_special_characters_in_pii() {
        let jr = JsonRedactor::new(test_redactor());
        let input = r#"{"email": "user+tag@domain.com"}"#;
        let result = jr.redact_json(input).unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let email = parsed["email"].as_str().unwrap();
        // Structured redaction: local part redacted, domain redacted, TLD preserved
        assert!(email.contains("@"));
        assert!(email.contains(".com"));
        assert!(!email.contains("user"));
    }

    #[test]
    fn test_phone_detection_through_redactor() {
        let r = test_redactor();
        // Direct test of redactor on phone string
        let input = "+12025550123";
        let result = r.redact(input);
        assert_ne!(input, result.as_ref());
    }
}
