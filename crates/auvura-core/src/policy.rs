use crate::types::PiiType;
use std::collections::{HashMap, HashSet};

/// Redaction policy – defines WHAT to redact and HOW to redact it
#[derive(Debug, Clone)]
pub struct RedactionPolicy {
    /// Enabled PII types (default: all high-confidence types)
    enabled_types: HashSet<PiiType>,
    
    /// Custom placeholder per PII type (overrides defaults)
    placeholder_map: HashMap<PiiType, String>,
    
    /// Allowlist: terms NEVER redacted (e.g., "Apple", "Paris")
    allowlist: Vec<String>,
    
    /// Blocklist: terms ALWAYS redacted (e.g., known employee names)
    blocklist: Vec<String>,
    
    /// Require validation for types that support it (e.g., Luhn check)
    strict_validation: bool,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        let mut enabled = HashSet::new();
        enabled.insert(PiiType::Email);
        enabled.insert(PiiType::PhoneNumber);
        enabled.insert(PiiType::Ssn);
        enabled.insert(PiiType::CreditCard);
        enabled.insert(PiiType::IpAddressV4);
        enabled.insert(PiiType::IpAddressV6);

        Self {
            enabled_types: enabled,
            placeholder_map: HashMap::new(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            strict_validation: true, // Fail-safe default
        }
    }
}

impl RedactionPolicy {
    /// Builder pattern for ergonomic configuration
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }

    /// Check if a PII type should be scanned for
    pub fn is_enabled(&self, pii_type: PiiType) -> bool {
        self.enabled_types.contains(&pii_type)
    }

    /// Get redaction placeholder for a PII type
    pub fn placeholder_for(&self, pii_type: PiiType) -> &str {
        self.placeholder_map
            .get(&pii_type)
            .map(String::as_str)
            .unwrap_or_else(|| pii_type.placeholder())
    }

    /// Check if text is in allowlist (should NEVER be redacted)
    pub fn is_allowed(&self, text: &str) -> bool {
        self.allowlist.iter().any(|term| text.contains(term))
    }

    /// Check if text is in blocklist (should ALWAYS be redacted)
    pub fn is_blocked(&self, text: &str) -> bool {
        self.blocklist.iter().any(|term| text.contains(term))
    }

    /// Whether to require validation (e.g., Luhn check) before redacting
    pub fn requires_validation(&self) -> bool {
        self.strict_validation
    }
}

/// Builder for RedactionPolicy – enables fluent configuration
#[derive(Default)]
pub struct PolicyBuilder {
    policy: RedactionPolicy,
}

impl PolicyBuilder {
    pub fn enable(mut self, pii_type: PiiType) -> Self {
        self.policy.enabled_types.insert(pii_type);
        self
    }

    pub fn disable(mut self, pii_type: PiiType) -> Self {
        self.policy.enabled_types.remove(&pii_type);
        self
    }

    pub fn with_placeholder(mut self, pii_type: PiiType, placeholder: &str) -> Self {
        self.policy.placeholder_map.insert(pii_type, placeholder.to_string());
        self
    }

    pub fn with_allowlist(mut self, terms: Vec<&str>) -> Self {
        self.policy.allowlist = terms.into_iter().map(String::from).collect();
        self
    }

    pub fn with_blocklist(mut self, terms: Vec<&str>) -> Self {
        self.policy.blocklist = terms.into_iter().map(String::from).collect();
        self
    }

    pub fn strict_validation(mut self, enabled: bool) -> Self {
        self.policy.strict_validation = enabled;
        self
    }

    pub fn build(self) -> RedactionPolicy {
        self.policy
    }
}

/// Predefined compliance profiles (GDPR, HIPAA, PCI-DSS)
impl RedactionPolicy {
    /// GDPR profile: Focus on identifiers + online identifiers
    pub fn gdpr() -> Self {
        PolicyBuilder::default()
            .enable(PiiType::Email)
            .enable(PiiType::PhoneNumber)
            .enable(PiiType::IpAddressV4)
            .enable(PiiType::IpAddressV6)
            .disable(PiiType::Ssn) // US-specific
            .build()
    }

    /// HIPAA profile: Focus on US health identifiers
    pub fn hipaa() -> Self {
        PolicyBuilder::default()
            .enable(PiiType::Ssn)
            .enable(PiiType::PhoneNumber)
            .enable(PiiType::IpAddressV4)
            .with_allowlist(vec!["hospital", "clinic", "medical center"])
            .build()
    }

    /// PCI-DSS profile: Credit card focus
    pub fn pci_dss() -> Self {
        PolicyBuilder::default()
            .enable(PiiType::CreditCard)
            .strict_validation(true) // MUST validate with Luhn
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_enables_all_core_types() {
        let policy = RedactionPolicy::default();
        assert!(policy.is_enabled(PiiType::Email));
        assert!(policy.is_enabled(PiiType::CreditCard));
        assert!(policy.is_enabled(PiiType::Ssn));
    }

    #[test]
    fn test_custom_placeholder() {
        let policy = PolicyBuilder::default()
            .with_placeholder(PiiType::Email, "█".repeat(10).as_str())
            .build();
        
        assert_eq!(policy.placeholder_for(PiiType::Email), "██████████");
        assert_eq!(policy.placeholder_for(PiiType::Ssn), "[REDACTED_SSN]"); // unchanged
    }

    #[test]
    fn test_allowlist_prevents_redaction() {
        let policy = PolicyBuilder::default()
            .with_allowlist(vec!["Apple Inc", "Paris"])
            .build();
        
        assert!(policy.is_allowed("Contact Apple Inc support"));
        assert!(!policy.is_allowed("Contact John Doe")); // not in allowlist
    }

    #[test]
    fn test_gdpr_profile_excludes_ssn() {
        let policy = RedactionPolicy::gdpr();
        assert!(!policy.is_enabled(PiiType::Ssn));
        assert!(policy.is_enabled(PiiType::IpAddressV4));
    }

    #[test]
    fn test_pci_requires_validation() {
        let policy = RedactionPolicy::pci_dss();
        assert!(policy.requires_validation());
    }
}
