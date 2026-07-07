use crate::{
    audit::{AuditEvent, AuditLogger, NoopAuditLogger},
    detector::{Detection, MultiDetector, PiiDetector},
    policy::{RedactionMode, RedactionPolicy},
    types::PiiType,
};
use std::borrow::Cow;
use std::sync::Arc;

/// Helper enum to track what kind of redaction to apply at a span
enum RedactionKind<'a> {
    Pii(&'a Detection),
    Blocklist,
}

/// Core redaction engine – orchestrates policy, detection, and redaction
pub struct Redactor {
    detector: MultiDetector,
    policy: RedactionPolicy,
    audit_logger: Arc<dyn AuditLogger>,
}

/// Check if a match at `start..end` in `text` is at a word boundary.
/// A word boundary means the character before is non-alphanumeric (or start)
/// and the character after is non-alphanumeric (or end).
fn is_word_boundary_match(text: &str, start: usize, end: usize) -> bool {
    let before_ok = start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric();
    let after_ok = end >= text.len() || !text.as_bytes()[end].is_ascii_alphanumeric();
    before_ok && after_ok
}

impl Redactor {
    /// Create a new redactor with detectors and policy
    pub fn new(detectors: Vec<Box<dyn PiiDetector>>, policy: RedactionPolicy) -> Self {
        Self {
            detector: MultiDetector::new(detectors),
            policy,
            audit_logger: Arc::new(NoopAuditLogger),
        }
    }

    /// Create a new redactor with an audit logger for compliance logging.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auvura_core::redactor::Redactor;
    /// use auvura_core::audit::JsonAuditLogger;
    /// use auvura_core::policy::RedactionPolicy;
    ///
    /// let logger = JsonAuditLogger::new();
    /// let redactor = Redactor::with_audit_logger(vec![], RedactionPolicy::default(), logger);
    /// ```
    pub fn with_audit_logger(
        detectors: Vec<Box<dyn PiiDetector>>,
        policy: RedactionPolicy,
        audit_logger: impl AuditLogger + 'static,
    ) -> Self {
        Self {
            detector: MultiDetector::new(detectors),
            policy,
            audit_logger: Arc::new(audit_logger),
        }
    }

    /// Get a reference to the audit logger.
    pub fn audit_logger(&self) -> &dyn AuditLogger {
        self.audit_logger.as_ref()
    }

    /// Redact PII from text – returns Cow<str> for zero-copy optimization
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if text.is_empty() {
            return Cow::Borrowed(text);
        }

        // Step 1: Find allowlist spans on ORIGINAL text (before any modification)
        let allowlist_spans = self.find_allowlist_spans(text);

        // Step 2: Run detectors on ORIGINAL text (not modified by blocklist)
        // Pass validation flag from policy
        let detections = self
            .detector
            .detect_with_validation(text, self.policy.requires_validation());

        // Step 2b: Filter out detections for disabled PII types
        let enabled_detections: Vec<Detection> = detections
            .into_iter()
            .filter(|d| self.policy.is_enabled(d.pii_type))
            .collect();

        // Step 3: Filter detections - remove those overlapping with allowlist
        let filtered_detections: Vec<Detection> = enabled_detections
            .into_iter()
            .filter(|d| {
                !allowlist_spans
                    .iter()
                    .any(|&(start, end)| d.start < end && d.end > start)
            })
            .collect();

        // Step 4: Find blocklist spans on ORIGINAL text, filter by allowlist
        let blocklist_spans: Vec<(usize, usize)> = self
            .policy
            .blocklist_terms()
            .iter()
            .flat_map(|term| {
                let allowlist = &allowlist_spans;
                text.match_indices(term.as_str())
                    .filter_map(move |(start, _)| {
                        let end = start + term.len();
                        // Only match whole words — skip partial matches like
                        // "CONFIDENTIAL" inside "CONFIDENTIALITY"
                        if !is_word_boundary_match(text, start, end) {
                            return None;
                        }
                        let overlaps_allowlist = allowlist
                            .iter()
                            .any(|&(a_start, a_end)| start < a_end && end > a_start);
                        if overlaps_allowlist {
                            None
                        } else {
                            Some((start, end))
                        }
                    })
            })
            .collect();

        // Step 5: If nothing to redact, return original
        if filtered_detections.is_empty() && blocklist_spans.is_empty() {
            self.audit_logger.log(AuditEvent::RequestProcessed {
                had_pii: false,
                detection_count: 0,
                redacted: false,
            });
            return Cow::Borrowed(text);
        }

        // Step 6: Apply all redactions in one pass over the original text
        let mut result = String::with_capacity(text.len());
        let mut last_idx = 0;
        let mut pii_counter: usize = 0;

        // Merge PII detections and blocklist spans into sorted list
        let mut all_spans: Vec<(usize, usize, RedactionKind<'_>)> = Vec::new();

        for d in &filtered_detections {
            all_spans.push((d.start, d.end, RedactionKind::Pii(d)));
        }
        for &(start, end) in &blocklist_spans {
            all_spans.push((start, end, RedactionKind::Blocklist));
        }

        all_spans.sort_by_key(|&(start, _, _)| start);

        for (start, end, kind) in all_spans {
            if start > last_idx {
                result.push_str(&text[last_idx..start]);
            }

            match kind {
                RedactionKind::Pii(detection) => {
                    let redacted = if self.policy.mode() == RedactionMode::Tokenize {
                        // Tokenize mode: replace with sequential tokens
                        let token = format!("[[PII_{}]]", pii_counter);
                        pii_counter += 1;
                        token
                    } else {
                        self.redact_structured(&detection.original, detection.pii_type)
                    };
                    self.audit_logger
                        .log(AuditEvent::from_detection(detection, &redacted));
                    result.push_str(&redacted);
                }
                RedactionKind::Blocklist => {
                    result.push_str(&"█".repeat(end - start));
                }
            }

            last_idx = end;
        }

        if last_idx < text.len() {
            result.push_str(&text[last_idx..]);
        }

        // Log the request processed event
        self.audit_logger.log(AuditEvent::RequestProcessed {
            had_pii: !filtered_detections.is_empty(),
            detection_count: filtered_detections.len(),
            redacted: true,
        });

        Cow::Owned(result)
    }

    fn find_allowlist_spans(&self, text: &str) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        for term in self.policy.allowlist_terms() {
            for (start, _) in text.match_indices(term.as_str()) {
                let end = start + term.len();
                // Only protect whole-word allowlist matches
                if is_word_boundary_match(text, start, end) {
                    spans.push((start, end));
                }
            }
        }
        spans
    }

    fn redact_structured(&self, original: &str, pii_type: PiiType) -> String {
        // If a custom placeholder is configured, use it for simple replacement
        if let Some(custom) = self.policy.custom_placeholder(pii_type) {
            return custom.to_string();
        }

        // Apply global redaction mode
        match self.policy.mode() {
            RedactionMode::Mask => {
                // Default: format-preserving structured redaction
                match pii_type {
                    PiiType::Email => self.redact_email_structured(original),
                    PiiType::PhoneNumber => self.redact_phone_structured(original),
                    PiiType::Ssn => self.redact_ssn_structured(original),
                    PiiType::CreditCard => self.redact_credit_card_structured(original),
                    PiiType::IpAddressV4 | PiiType::IpAddressV6 => "█".repeat(original.len()),
                    PiiType::Iban => self.redact_iban_structured(original),
                    PiiType::PassportNumber => self.redact_passport_structured(original),
                    PiiType::NationalId => self.redact_national_id_structured(original),
                    PiiType::PhysicalAddress => "█".repeat(original.len()),
                    PiiType::Other(_) => "█".repeat(original.len()),
                }
            }
            RedactionMode::Replace => {
                // Full replacement with type-specific placeholder
                pii_type.placeholder().to_string()
            }
            RedactionMode::Hash => {
                // Blake3 hash (first 16 hex chars for readability)
                let hash = blake3::hash(original.as_bytes());
                let hex = hash.to_hex();
                format!("[HASH:{}]", &hex[..16])
            }
            RedactionMode::Tokenize => {
                // Tokenize with sequential numbers - handled at redact() level
                // This fallback should not be reached
                format!("[PII:{}]", original.len())
            }
        }
    }

    fn redact_email_structured(&self, email: &str) -> String {
        if let Some(at_idx) = email.find('@') {
            let (local, domain) = email.split_at(at_idx);
            let domain = &domain[1..];

            let local_redacted: String = local
                .chars()
                .map(|c| if c == '.' { '.' } else { '█' })
                .collect();

            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() >= 2 {
                let tld = parts.last().unwrap();
                let main = parts[..parts.len() - 1].join(".");
                let main_redacted = "█".repeat(main.len());
                format!("{}@{}.{}", local_redacted, main_redacted, tld)
            } else {
                format!("{}@{}", local_redacted, "█".repeat(domain.len()))
            }
        } else {
            "█".repeat(email.len())
        }
    }

    fn redact_phone_structured(&self, phone: &str) -> String {
        phone
            .chars()
            .map(|c| if c.is_ascii_digit() { '█' } else { c })
            .collect()
    }

    fn redact_ssn_structured(&self, ssn: &str) -> String {
        ssn.chars()
            .map(|c| if c.is_ascii_digit() { '█' } else { c })
            .collect()
    }

    fn redact_credit_card_structured(&self, cc: &str) -> String {
        let digits: Vec<char> = cc.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() < 4 {
            return "█".repeat(cc.len());
        }

        let mut result = String::new();
        let mut digit_count = 0;
        for c in cc.chars() {
            if c.is_ascii_digit() {
                digit_count += 1;
                if digit_count > digits.len() - 4 {
                    result.push(c);
                } else {
                    result.push('█');
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    fn redact_iban_structured(&self, iban: &str) -> String {
        // Show country code and last 4 chars, redact middle
        let cleaned: String = iban
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        if cleaned.len() < 8 {
            return "█".repeat(iban.len());
        }

        let country = &cleaned[0..2];
        let last4 = &cleaned[cleaned.len() - 4..];
        let middle_len = cleaned.len() - 6; // country(2) + check(2) + last4(4)

        let mut result = String::new();
        result.push_str(country);
        result.push_str(&"█".repeat(middle_len));
        result.push_str(last4);

        // Preserve original spacing if any
        if iban.contains(' ') {
            result
                .chars()
                .collect::<Vec<_>>()
                .chunks(4)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            result
        }
    }

    fn redact_passport_structured(&self, passport: &str) -> String {
        // Show leading letters, redact digits
        let mut result = String::new();
        let mut found_digit = false;
        for c in passport.chars() {
            if c.is_ascii_digit() {
                found_digit = true;
                result.push('█');
            } else if !found_digit {
                result.push(c);
            } else {
                result.push('█');
            }
        }
        result
    }

    fn redact_national_id_structured(&self, id: &str) -> String {
        // Show last 4 digits, redact rest
        let digits: Vec<char> = id.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() < 4 {
            return "█".repeat(id.len());
        }

        let mut result = String::new();
        let mut digit_count = 0;
        for c in id.chars() {
            if c.is_ascii_digit() {
                digit_count += 1;
                if digit_count > digits.len() - 4 {
                    result.push(c);
                } else {
                    result.push('█');
                }
            } else {
                result.push(c);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::PiiDetector;
    use crate::types::PiiType;

    // Minimal email detector
    struct SimpleEmailDetector;
    impl PiiDetector for SimpleEmailDetector {
        fn pii_type(&self) -> PiiType {
            PiiType::Email
        }

        fn confidence(&self) -> crate::detector::Confidence {
            crate::detector::Confidence::High
        }

        fn detect(&self, text: &str) -> Vec<Detection> {
            let mut detections = Vec::new();
            for (start, _) in text.match_indices('@') {
                let word_start = text[..start]
                    .rfind(|c: char| c.is_whitespace() || c == '<')
                    .map_or(0, |i| i + 1);
                let word_end = text[start..]
                    .find(|c: char| c.is_whitespace() || c == '>' || c == ',')
                    .map_or(text.len(), |i| start + i);

                if word_end > word_start && word_end <= text.len() {
                    detections.push(Detection {
                        pii_type: PiiType::Email,
                        confidence: self.confidence(),
                        start: word_start,
                        end: word_end,
                        original: text[word_start..word_end].to_string(),
                    });
                }
            }
            detections
        }
    }

    #[test]
    fn test_zero_copy_when_no_pii() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Hello world";
        let result = redactor.redact(input);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "Hello world");
    }

    #[test]
    fn test_structured_email_redaction() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        // "john.doe" = 4 chars (john) + '.' + 3 chars (doe) = 8 chars total
        // Redaction: "████.███" (4 █ + '.' + 3 █)
        // "example.com" → "███████.com" (7 █ for "example" + preserved TLD)
        let input = "Contact john.doe@example.com for help";
        let result = redactor.redact(input);
        assert_eq!(result, "Contact ████.███@███████.com for help");
    }

    #[test]
    fn test_allowlist_prevents_redaction() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_allowlist(vec!["support@example.com"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Email support@example.com or john.doe@example.com";
        let result = redactor.redact(input);
        assert!(result.contains("support@example.com"));
        assert!(result.contains("@███████.com")); // john.doe redacted
    }

    #[test]
    fn test_blocklist_forces_redaction() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["CONFIDENTIAL"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Mark this CONFIDENTIAL";
        let result = redactor.redact(input);
        assert_eq!(result, "Mark this ████████████");
    }

    #[test]
    fn test_blocklist_does_not_break_pii_detection() {
        // Regression test: blocklist must not modify text before PII detection
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["example"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        // "example" is in blocklist, but the email should still be detected
        // and redacted properly (not broken by blocklist replacement)
        let input = "Email: john@example.com";
        let result = redactor.redact(input);
        // Email should be redacted with structured format
        assert!(result.contains("@"));
        assert!(result.contains(".com"));
        // Blocklist "example" should also be redacted
        assert!(!result.contains("example"));
    }

    #[test]
    fn test_blocklist_and_pii_both_redacted() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["SPAM"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "SPAM Email: john@example.com";
        let result = redactor.redact(input);
        // Both blocklist and PII should be redacted
        assert!(!result.contains("SPAM"));
        assert!(result.contains("@"));
    }

    #[test]
    fn test_disabled_pii_type_not_redacted() {
        // Test that disabling a PII type via policy actually works
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder().disable(PiiType::Email).build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Email: john@example.com";
        let result = redactor.redact(input);
        // Email should NOT be redacted since we disabled Email type
        assert_eq!(result, input);
    }

    #[test]
    fn test_enabled_pii_type_is_redacted() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder().enable(PiiType::Email).build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Email: john@example.com";
        let result = redactor.redact(input);
        // Email should be redacted since Email type is enabled (explicitly)
        assert!(result.contains("@███████.com"));
    }

    #[test]
    fn test_ssn_structured_redaction() {
        struct SsnDetector;
        impl PiiDetector for SsnDetector {
            fn pii_type(&self) -> PiiType {
                PiiType::Ssn
            }
            fn confidence(&self) -> crate::detector::Confidence {
                crate::detector::Confidence::High
            }
            fn detect(&self, text: &str) -> Vec<Detection> {
                // Simple SSN pattern without regex: look for "###-##-####"
                let mut detections = Vec::new();
                let bytes = text.as_bytes();
                for i in 0..bytes.len().saturating_sub(10) {
                    if bytes[i].is_ascii_digit()
                        && bytes[i + 1].is_ascii_digit()
                        && bytes[i + 2].is_ascii_digit()
                        && bytes[i + 3] == b'-'
                        && bytes[i + 4].is_ascii_digit()
                        && bytes[i + 5].is_ascii_digit()
                        && bytes[i + 6] == b'-'
                        && bytes[i + 7].is_ascii_digit()
                        && bytes[i + 8].is_ascii_digit()
                        && bytes[i + 9].is_ascii_digit()
                        && bytes[i + 10].is_ascii_digit()
                    {
                        // Verify boundaries (not part of longer digit sequence)
                        let start = i;
                        let end = i + 11;
                        if (start == 0 || !bytes[start - 1].is_ascii_digit())
                            && (end == bytes.len() || !bytes[end].is_ascii_digit())
                        {
                            detections.push(Detection {
                                pii_type: PiiType::Ssn,
                                confidence: self.confidence(),
                                start,
                                end,
                                original: text[start..end].to_string(),
                            });
                        }
                    }
                }
                detections
            }
        }

        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(SsnDetector)], policy);

        let input = "SSN: 123-45-6789";
        let result = redactor.redact(input);
        assert_eq!(result, "SSN: ███-██-████");
    }

    #[test]
    fn test_credit_card_last_four() {
        struct CcDetector;
        impl PiiDetector for CcDetector {
            fn pii_type(&self) -> PiiType {
                PiiType::CreditCard
            }
            fn confidence(&self) -> crate::detector::Confidence {
                crate::detector::Confidence::High
            }
            fn detect(&self, text: &str) -> Vec<Detection> {
                // For test purposes: detect exact test pattern
                // Real detector will use regex in detectors/credit_card.rs later
                if let Some(start) = text.find("4111 1111 1111 1111") {
                    return vec![Detection {
                        pii_type: PiiType::CreditCard,
                        confidence: self.confidence(),
                        start,
                        end: start + 19, // length of "4111 1111 1111 1111"
                        original: "4111 1111 1111 1111".to_string(),
                    }];
                }
                vec![]
            }
        }

        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(CcDetector)], policy);

        let input = "Card: 4111 1111 1111 1111";
        let result = redactor.redact(input);
        assert_eq!(result, "Card: ████ ████ ████ 1111");
    }

    #[test]
    fn test_strict_validation_skips_invalid_cards_when_enabled() {
        // When strict_validation is true (default), invalid Luhn numbers should not be detected
        struct TestCcDetector;
        impl PiiDetector for TestCcDetector {
            fn pii_type(&self) -> PiiType {
                PiiType::CreditCard
            }
            fn confidence(&self) -> crate::detector::Confidence {
                crate::detector::Confidence::High
            }
            fn detect(&self, text: &str) -> Vec<Detection> {
                self.detect_with_validation(text, true)
            }
            fn detect_with_validation(&self, text: &str, validate: bool) -> Vec<Detection> {
                if let Some(start) = text.find("1234567890123456") {
                    let candidate = "1234567890123456";
                    // Simulate validation failure when validate=true
                    if validate {
                        return vec![];
                    }
                    return vec![Detection {
                        pii_type: PiiType::CreditCard,
                        confidence: self.confidence(),
                        start,
                        end: start + 16,
                        original: candidate.to_string(),
                    }];
                }
                vec![]
            }
        }

        let policy = RedactionPolicy::default(); // strict_validation = true by default
        let redactor = Redactor::new(vec![Box::new(TestCcDetector)], policy);

        let input = "Card: 1234567890123456";
        let result = redactor.redact(input);
        // Should NOT redact since validation fails
        assert_eq!(result, input);
    }

    #[test]
    fn test_strict_validation_allows_invalid_cards_when_disabled() {
        struct TestCcDetector;
        impl PiiDetector for TestCcDetector {
            fn pii_type(&self) -> PiiType {
                PiiType::CreditCard
            }
            fn confidence(&self) -> crate::detector::Confidence {
                crate::detector::Confidence::High
            }
            fn detect(&self, text: &str) -> Vec<Detection> {
                self.detect_with_validation(text, true)
            }
            fn detect_with_validation(&self, text: &str, validate: bool) -> Vec<Detection> {
                if let Some(start) = text.find("1234567890123456") {
                    let candidate = "1234567890123456";
                    // Simulate validation failure when validate=true
                    if validate {
                        return vec![];
                    }
                    return vec![Detection {
                        pii_type: PiiType::CreditCard,
                        confidence: self.confidence(),
                        start,
                        end: start + 16,
                        original: candidate.to_string(),
                    }];
                }
                vec![]
            }
        }

        let policy = RedactionPolicy::builder()
            .strict_validation(false) // Disable validation
            .build();
        let redactor = Redactor::new(vec![Box::new(TestCcDetector)], policy);

        let input = "Card: 1234567890123456";
        let result = redactor.redact(input);
        // Should redact even though validation would fail
        assert_ne!(result, input);
    }

    #[test]
    fn test_custom_placeholder_overrides_structured_redaction() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_placeholder(PiiType::Email, "[EMAIL]")
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Contact john@example.com";
        let result = redactor.redact(input);
        // Custom placeholder used instead of structured "████.███@███████.com"
        assert_eq!(result, "Contact [EMAIL]");
    }

    #[test]
    fn test_custom_placeholder_per_type() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_placeholder(PiiType::Email, "***EMAIL***")
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Email: john@example.com";
        let result = redactor.redact(input);
        assert_eq!(result, "Email: ***EMAIL***");
    }

    #[test]
    fn test_structured_redaction_used_when_no_custom_placeholder() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::default();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Contact john.doe@example.com";
        let result = redactor.redact(input);
        // Default: format-preserving structured redaction
        assert_eq!(result, "Contact ████.███@███████.com");
    }

    #[test]
    fn test_blocklist_does_not_match_word_substring() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["CONFIDENTIAL"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        // "CONFIDENTIALITY" contains "CONFIDENTIAL" but is a different word
        let input = "This document is CONFIDENTIALITY";
        let result = redactor.redact(input);
        assert_eq!(result, input); // Nothing should be redacted
    }

    #[test]
    fn test_blocklist_matches_whole_word() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["CONFIDENTIAL"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Mark this CONFIDENTIAL please";
        let result = redactor.redact(input);
        assert_eq!(result, "Mark this ████████████ please");
    }

    #[test]
    fn test_blocklist_word_boundary_with_punctuation() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["SECRET"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        // Punctuation is a word boundary — "SECRET." should match
        let input = "Keep this SECRET.";
        let result = redactor.redact(input);
        assert_eq!(result, "Keep this ██████.");

        // "SECRETS" should NOT match (different word)
        let input2 = "Keep these SECRETS safe";
        let result2 = redactor.redact(input2);
        assert_eq!(result2, input2);
    }

    #[test]
    fn test_allowlist_word_boundary_prevents_redaction() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["APPLE"])
            .with_allowlist(vec!["APPLE"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        // "APPLE" in allowlist should prevent redaction of the whole word
        let input = "I like APPLE pie";
        let result = redactor.redact(input);
        assert_eq!(result, "I like APPLE pie");

        // But "APPLE" inside "PINEAPPLE" should NOT be protected
        let input2 = "I like PINEAPPLE pie";
        let result2 = redactor.redact(input2);
        assert_eq!(result2, "I like PINEAPPLE pie");
    }

    #[test]
    fn test_blocklist_multiple_terms_word_boundary() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["TOP", "SECRET"])
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "TOP SECRET info: TOPSECRET is not matched";
        let result = redactor.redact(input);
        // "TOP" and "SECRET" as standalone words are redacted
        // "TOPSECRET" is one word — no match
        assert_eq!(result, "███ ██████ info: TOPSECRET is not matched");
    }

    #[test]
    fn test_redaction_mode_replace() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_mode(crate::policy::RedactionMode::Replace)
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Contact john@example.com";
        let result = redactor.redact(input);
        // Replace mode uses the default placeholder for the type
        assert_eq!(result, "Contact [REDACTED_EMAIL]");
    }

    #[test]
    fn test_redaction_mode_hash() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_mode(crate::policy::RedactionMode::Hash)
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Contact john@example.com";
        let result = redactor.redact(input);
        // Hash mode produces a deterministic Blake3 hash
        assert!(result.starts_with("Contact [HASH:"));
        assert!(result.ends_with("]"));
        // Same input produces same hash
        let result2 = redactor.redact(input);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_redaction_mode_tokenize() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_mode(crate::policy::RedactionMode::Tokenize)
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Email alice@example.com and bob@test.org";
        let result = redactor.redact(input);
        // Tokenize mode replaces with sequential tokens
        assert!(result.contains("[[PII_0]]"));
        assert!(result.contains("[[PII_1]]"));
        assert!(!result.contains("alice@example.com"));
        assert!(!result.contains("bob@test.org"));
    }

    #[test]
    fn test_redaction_mode_tokenize_sequential() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_mode(crate::policy::RedactionMode::Tokenize)
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "a@b.com c@d.com e@f.com";
        let result = redactor.redact(input);
        // Tokens should be sequential
        assert!(result.contains("[[PII_0]]"));
        assert!(result.contains("[[PII_1]]"));
        assert!(result.contains("[[PII_2]]"));
    }

    #[test]
    fn test_redaction_mode_replace_with_custom_placeholder() {
        let detector = SimpleEmailDetector;
        let policy = RedactionPolicy::builder()
            .with_mode(crate::policy::RedactionMode::Replace)
            .with_placeholder(PiiType::Email, "[MAIL]")
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "Contact john@example.com";
        let result = redactor.redact(input);
        // Custom placeholder overrides the default
        assert_eq!(result, "Contact [MAIL]");
    }
}
