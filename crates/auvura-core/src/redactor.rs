use crate::{
    detector::{Detection, MultiDetector, PiiDetector},
    policy::RedactionPolicy,
    types::PiiType,
};
use std::borrow::Cow;

/// Core redaction engine – orchestrates policy, detection, and redaction
pub struct Redactor {
    detector: MultiDetector,
    policy: RedactionPolicy,
}

impl Redactor {
    /// Create a new redactor with detectors and policy
    pub fn new(detectors: Vec<Box<dyn PiiDetector>>, policy: RedactionPolicy) -> Self {
        Self {
            detector: MultiDetector::new(detectors),
            policy,
        }
    }

    /// Redact PII from text – returns Cow<str> for zero-copy optimization
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if text.is_empty() {
            return Cow::Borrowed(text);
        }

        // Step 1: Apply blocklist replacements
        let mut working_text = text.to_string();
        let mut blocklist_applied = false;
        for term in self.policy.blocklist_terms() {
            if working_text.contains(term.as_str()) {
                working_text = working_text.replace(term.as_str(), &"█".repeat(term.len()));
                blocklist_applied = true;
            }
        }

        // Step 2: Find allowlist spans
        let allowlist_spans = self.find_allowlist_spans(&working_text);

        // Step 3: Run detectors
        let detections = self.detector.detect(&working_text);

        // Step 4: Filter detections overlapping with allowlist
        let filtered_detections: Vec<Detection> = detections
            .into_iter()
            .filter(|d| {
                !allowlist_spans
                    .iter()
                    .any(|&(start, end)| d.start < end && d.end > start)
            })
            .collect();

        // Step 5: Zero-copy path if no changes
        if filtered_detections.is_empty() && !blocklist_applied {
            return Cow::Borrowed(text);
        }

        // Step 6: Apply redactions (always returns owned String)
        if filtered_detections.is_empty() {
            return Cow::Owned(working_text);
        }

        Cow::Owned(self.apply_redactions(&working_text, &filtered_detections))
    }

    fn find_allowlist_spans(&self, text: &str) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        for term in self.policy.allowlist_terms() {
            for (start, _) in text.match_indices(term.as_str()) {
                let end = start + term.len();
                spans.push((start, end));
            }
        }
        spans
    }

    fn apply_redactions(&self, text: &str, detections: &[Detection]) -> String {
        let mut result = String::with_capacity(text.len());
        let mut last_idx = 0;

        for detection in detections {
            if detection.start > last_idx {
                result.push_str(&text[last_idx..detection.start]);
            }

            let redacted = self.redact_structured(&detection.original, detection.pii_type);
            result.push_str(&redacted);

            last_idx = detection.end;
        }

        if last_idx < text.len() {
            result.push_str(&text[last_idx..]);
        }

        result
    }

    fn redact_structured(&self, original: &str, pii_type: PiiType) -> String {
        match pii_type {
            PiiType::Email => self.redact_email_structured(original),
            PiiType::PhoneNumber => self.redact_phone_structured(original),
            PiiType::Ssn => self.redact_ssn_structured(original),
            PiiType::CreditCard => self.redact_credit_card_structured(original),
            PiiType::IpAddressV4 | PiiType::IpAddressV6 => "█".repeat(original.len()),
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

        fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
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
    fn test_ssn_structured_redaction() {
        struct SsnDetector;
        impl PiiDetector for SsnDetector {
            fn pii_type(&self) -> PiiType {
                PiiType::Ssn
            }
            fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
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
            fn detect<'a>(&self, text: &'a str) -> Vec<Detection> {
                // For test purposes: detect exact test pattern
                // Real detector will use regex in detectors/credit_card.rs later
                if let Some(start) = text.find("4111 1111 1111 1111") {
                    return vec![Detection {
                        pii_type: PiiType::CreditCard,
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
}
