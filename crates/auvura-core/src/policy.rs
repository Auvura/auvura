use crate::types::{PiiType, PiiTypeConfig};
use std::collections::{HashMap, HashSet};

/// Redaction mode – determines HOW PII is transformed
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    /// Format-preserving mask (default): replaces digits with `█` while
    /// keeping structure like `███-██-████` for SSNs
    #[default]
    Mask,
    /// Full replacement: replaces entire match with a placeholder string
    Replace,
    /// Hash: replaces with Blake3 hash of the original value (hex-encoded, first 16 chars)
    Hash,
    /// Tokenize: replaces with sequential tokens `[[PII_0]]`, `[[PII_1]]`, etc.
    Tokenize,
}

impl RedactionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mask => "mask",
            Self::Replace => "replace",
            Self::Hash => "hash",
            Self::Tokenize => "tokenize",
        }
    }
}

impl std::fmt::Display for RedactionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Redaction policy – defines WHAT to redact and HOW to redact it
#[derive(Debug, Clone)]
pub struct RedactionPolicy {
    /// Enabled PII types (default: all high-confidence types)
    enabled_types: HashSet<PiiType>,

    /// Custom placeholder per PII type (overrides defaults)
    placeholder_map: HashMap<PiiType, String>,

    /// Global redaction mode (default: Mask)
    mode: RedactionMode,

    /// Allowlist: terms NEVER redacted (e.g., "Apple", "Paris")
    allowlist: Vec<String>,

    /// Blocklist: terms ALWAYS redacted (e.g., known employee names)
    blocklist: Vec<String>,

    /// Require validation for types that support it (e.g., Luhn check)
    strict_validation: bool,
}

/// Serializable representation of `RedactionPolicy`.
///
/// Can be serialized to/from JSON, TOML, or any serde-supported format.
/// Use `RedactionPolicy::from_config()` to reconstruct a `RedactionPolicy`,
/// and `RedactionPolicy::serialize()` to convert back.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RedactionPolicyConfig {
    /// Enabled PII types
    #[serde(default)]
    pub enabled_types: Vec<PiiTypeConfig>,

    /// Custom placeholder per PII type
    #[serde(default)]
    pub placeholders: HashMap<PiiTypeConfig, String>,

    /// Global redaction mode (default: mask)
    #[serde(default)]
    pub mode: RedactionMode,

    /// Terms that should never be redacted
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Terms that must always be redacted
    #[serde(default)]
    pub blocklist: Vec<String>,

    /// Whether to require validation (e.g., Luhn check) before redacting
    #[serde(default = "default_strict_validation")]
    pub strict_validation: bool,
}

fn default_strict_validation() -> bool {
    true
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
        enabled.insert(PiiType::Iban);
        enabled.insert(PiiType::PassportNumber);
        enabled.insert(PiiType::NationalId);
        enabled.insert(PiiType::PhysicalAddress);

        Self {
            enabled_types: enabled,
            placeholder_map: HashMap::new(),
            mode: RedactionMode::default(),
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

    /// Get the global redaction mode
    pub fn mode(&self) -> RedactionMode {
        self.mode
    }

    /// Serialize this policy to a `RedactionPolicyConfig`.
    pub fn serialize(&self) -> RedactionPolicyConfig {
        RedactionPolicyConfig {
            enabled_types: self.enabled_types.iter().map(|t| (*t).into()).collect(),
            placeholders: self
                .placeholder_map
                .iter()
                .map(|(k, v)| ((*k).into(), v.clone()))
                .collect(),
            mode: self.mode,
            allowlist: self.allowlist.clone(),
            blocklist: self.blocklist.clone(),
            strict_validation: self.strict_validation,
        }
    }

    /// Reconstruct a `RedactionPolicy` from a serialized config.
    ///
    /// Unknown PII type names in `enabled_types` are silently ignored.
    /// `Other(...)` types from config are skipped (cannot convert back to `&'static str`).
    pub fn from_config(config: &RedactionPolicyConfig) -> Self {
        let enabled_types: HashSet<PiiType> = config
            .enabled_types
            .iter()
            .filter_map(|t| t.to_pii_type())
            .collect();

        let placeholder_map: HashMap<PiiType, String> = config
            .placeholders
            .iter()
            .filter_map(|(k, v)| k.to_pii_type().map(|p| (p, v.clone())))
            .collect();

        Self {
            enabled_types,
            placeholder_map,
            mode: config.mode,
            allowlist: config.allowlist.clone(),
            blocklist: config.blocklist.clone(),
            strict_validation: config.strict_validation,
        }
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

    /// Get custom placeholder if one is configured, otherwise None
    pub fn custom_placeholder(&self, pii_type: PiiType) -> Option<&str> {
        self.placeholder_map.get(&pii_type).map(String::as_str)
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

    /// Get allowlist terms (for span detection in redactor)
    pub fn allowlist_terms(&self) -> &[String] {
        &self.allowlist
    }

    /// Get blocklist terms (for exact-match redaction)
    pub fn blocklist_terms(&self) -> &[String] {
        &self.blocklist
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
        self.policy
            .placeholder_map
            .insert(pii_type, placeholder.to_string());
        self
    }

    pub fn with_mode(mut self, mode: RedactionMode) -> Self {
        self.policy.mode = mode;
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

    #[test]
    fn test_policy_config_round_trip_default() {
        let policy = RedactionPolicy::default();
        let config = policy.serialize();
        let restored = RedactionPolicy::from_config(&config);

        assert!(restored.is_enabled(PiiType::Email));
        assert!(restored.is_enabled(PiiType::PhoneNumber));
        assert!(restored.is_enabled(PiiType::Ssn));
        assert!(restored.is_enabled(PiiType::CreditCard));
        assert!(restored.is_enabled(PiiType::IpAddressV4));
        assert!(restored.is_enabled(PiiType::IpAddressV6));
        assert!(restored.requires_validation());
    }

    #[test]
    fn test_policy_config_round_trip_gdpr() {
        let policy = RedactionPolicy::gdpr();
        let config = policy.serialize();
        let restored = RedactionPolicy::from_config(&config);

        assert!(restored.is_enabled(PiiType::Email));
        assert!(restored.is_enabled(PiiType::PhoneNumber));
        assert!(restored.is_enabled(PiiType::IpAddressV4));
        assert!(!restored.is_enabled(PiiType::Ssn));
    }

    #[test]
    fn test_policy_config_round_trip_with_blocklist_allowlist() {
        let policy = RedactionPolicy::builder()
            .with_blocklist(vec!["SECRET", "CONFIDENTIAL"])
            .with_allowlist(vec!["Apple", "Google"])
            .build();

        let config = policy.serialize();
        let restored = RedactionPolicy::from_config(&config);

        assert_eq!(restored.blocklist_terms(), &["SECRET", "CONFIDENTIAL"]);
        assert_eq!(restored.allowlist_terms(), &["Apple", "Google"]);
    }

    #[test]
    fn test_policy_config_round_trip_with_placeholders() {
        let policy = RedactionPolicy::builder()
            .with_placeholder(PiiType::Email, "[MAIL]")
            .with_placeholder(PiiType::Ssn, "[SSN]")
            .build();

        let config = policy.serialize();
        let restored = RedactionPolicy::from_config(&config);

        assert_eq!(restored.custom_placeholder(PiiType::Email), Some("[MAIL]"));
        assert_eq!(restored.custom_placeholder(PiiType::Ssn), Some("[SSN]"));
        // CreditCard should have no custom placeholder
        assert_eq!(restored.custom_placeholder(PiiType::CreditCard), None);
    }

    #[test]
    fn test_policy_config_round_trip_strict_validation_false() {
        let policy = RedactionPolicy::builder().strict_validation(false).build();

        let config = policy.serialize();
        assert!(!config.strict_validation);

        let restored = RedactionPolicy::from_config(&config);
        assert!(!restored.requires_validation());
    }

    #[test]
    fn test_policy_config_serde_json() {
        let policy = RedactionPolicy::builder()
            .disable(PiiType::Ssn)
            .with_blocklist(vec!["SECRET"])
            .with_allowlist(vec!["Apple"])
            .strict_validation(false)
            .build();

        let config = policy.serialize();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: RedactionPolicyConfig = serde_json::from_str(&json).unwrap();
        let restored = RedactionPolicy::from_config(&parsed);

        assert!(restored.is_enabled(PiiType::Email));
        assert!(!restored.is_enabled(PiiType::Ssn));
        assert_eq!(restored.blocklist_terms(), &["SECRET"]);
        assert_eq!(restored.allowlist_terms(), &["Apple"]);
        assert!(!restored.requires_validation());
    }

    #[test]
    fn test_policy_config_from_json_string() {
        let json = r#"{
            "enabled_types": ["email", "phone_number", "credit_card"],
            "allowlist": ["test@example.com"],
            "blocklist": ["CONFIDENTIAL"],
            "strict_validation": true
        }"#;

        let config: RedactionPolicyConfig = serde_json::from_str(json).unwrap();
        let policy = RedactionPolicy::from_config(&config);

        assert!(policy.is_enabled(PiiType::Email));
        assert!(policy.is_enabled(PiiType::PhoneNumber));
        assert!(policy.is_enabled(PiiType::CreditCard));
        assert!(!policy.is_enabled(PiiType::Ssn));
        assert_eq!(policy.allowlist_terms(), &["test@example.com"]);
        assert_eq!(policy.blocklist_terms(), &["CONFIDENTIAL"]);
    }

    #[test]
    fn test_policy_config_empty_is_default() {
        let json = "{}";
        let config: RedactionPolicyConfig = serde_json::from_str(json).unwrap();
        let policy = RedactionPolicy::from_config(&config);

        // Empty config should result in no enabled types (no defaults injected)
        assert!(!policy.is_enabled(PiiType::Email));
        assert!(!policy.is_enabled(PiiType::Ssn));
    }

    #[test]
    fn test_policy_config_other_type_skipped() {
        let json = r#"{
            "enabled_types": ["email", {"other": "PERSON"}]
        }"#;

        let config: RedactionPolicyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.enabled_types.len(), 2);

        let policy = RedactionPolicy::from_config(&config);
        // "PERSON" Other type is skipped, only Email remains
        assert!(policy.is_enabled(PiiType::Email));
        assert!(!policy.is_enabled(PiiType::Ssn));
    }

    #[test]
    fn test_redaction_mode_default_is_mask() {
        let policy = RedactionPolicy::default();
        assert_eq!(policy.mode(), RedactionMode::Mask);
    }

    #[test]
    fn test_redaction_mode_builder() {
        let policy = PolicyBuilder::default()
            .with_mode(RedactionMode::Hash)
            .build();
        assert_eq!(policy.mode(), RedactionMode::Hash);
    }

    #[test]
    fn test_redaction_mode_round_trip() {
        let policy = PolicyBuilder::default()
            .with_mode(RedactionMode::Tokenize)
            .build();
        let config = policy.serialize();
        assert_eq!(config.mode, RedactionMode::Tokenize);

        let restored = RedactionPolicy::from_config(&config);
        assert_eq!(restored.mode(), RedactionMode::Tokenize);
    }

    #[test]
    fn test_redaction_mode_serde() {
        let modes = vec![
            (RedactionMode::Mask, "\"mask\""),
            (RedactionMode::Replace, "\"replace\""),
            (RedactionMode::Hash, "\"hash\""),
            (RedactionMode::Tokenize, "\"tokenize\""),
        ];

        for (mode, expected_json) in modes {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected_json);

            let parsed: RedactionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
    }
}
