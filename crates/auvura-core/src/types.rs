/// PII types with deterministic detection and regulatory grounding.
///
/// Design principles:
/// - Only types with regex + validation (minimal false negatives)
/// - Excludes contextual PII (names/addresses) requiring NER
/// - No heap allocations in enum (all variants are `Copy`)
/// - Regulatory basis documented for compliance auditing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiType {
    Email,
    PhoneNumber,
    Ssn, // US Social Security Number
    CreditCard,
    IpAddressV4,
    IpAddressV6,
    /// For NER-detected entities (names, organizations, locations)
    Other(&'static str), // Label like "PERSON", "ORG", "LOC"
}

/// Serializable representation of `PiiType`.
///
/// Uses `String` instead of `&'static str` for the `Other` variant,
/// enabling serde support without lifetime constraints.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiTypeConfig {
    Email,
    PhoneNumber,
    Ssn,
    CreditCard,
    IpAddressV4,
    IpAddressV6,
    Other(String),
}

impl From<PiiType> for PiiTypeConfig {
    fn from(p: PiiType) -> Self {
        match p {
            PiiType::Email => PiiTypeConfig::Email,
            PiiType::PhoneNumber => PiiTypeConfig::PhoneNumber,
            PiiType::Ssn => PiiTypeConfig::Ssn,
            PiiType::CreditCard => PiiTypeConfig::CreditCard,
            PiiType::IpAddressV4 => PiiTypeConfig::IpAddressV4,
            PiiType::IpAddressV6 => PiiTypeConfig::IpAddressV6,
            PiiType::Other(label) => PiiTypeConfig::Other(label.to_string()),
        }
    }
}

impl PiiTypeConfig {
    /// Convert back to `PiiType`. Returns `None` for `Other` variants
    /// whose label is not a `'static str` (i.e., deserialized from config).
    pub fn to_pii_type(&self) -> Option<PiiType> {
        match self {
            PiiTypeConfig::Email => Some(PiiType::Email),
            PiiTypeConfig::PhoneNumber => Some(PiiType::PhoneNumber),
            PiiTypeConfig::Ssn => Some(PiiType::Ssn),
            PiiTypeConfig::CreditCard => Some(PiiType::CreditCard),
            PiiTypeConfig::IpAddressV4 => Some(PiiType::IpAddressV4),
            PiiTypeConfig::IpAddressV6 => Some(PiiType::IpAddressV6),
            PiiTypeConfig::Other(_) => None, // Cannot convert back to &'static str
        }
    }
}

impl PiiType {
    /// Regulatory basis for compliance auditing
    pub fn regulatory_basis(&self) -> &'static str {
        match self {
            Self::Email => "GDPR Art.4(1), CCPA §1798.140(o)",
            Self::PhoneNumber => "GDPR Recital 30 + national telecom laws",
            Self::Ssn => "NIST SP 800-122 §2.1",
            Self::CreditCard => "PCI-DSS v4.0 + GDPR financial data",
            Self::IpAddressV4 | Self::IpAddressV6 => "GDPR Recital 30",
            Self::Other(_label) => "Contextual PII (NER-detected)",
        }
    }

    /// Default redaction placeholder (configurable later via Policy)
    pub fn placeholder(&self) -> &'static str {
        match self {
            Self::Email => "[REDACTED_EMAIL]",
            Self::PhoneNumber => "[REDACTED_PHONE]",
            Self::Ssn => "[REDACTED_SSN]",
            Self::CreditCard => "[REDACTED_CC]",
            Self::IpAddressV4 => "[REDACTED_IPv4]",
            Self::IpAddressV6 => "[REDACTED_IPv6]",
            Self::Other(_label) => "[REDACTED_OTHER]",
        }
    }

    /// Returns true if this PII type requires checksum validation
    /// (e.g., Luhn algorithm for credit cards)
    pub fn requires_validation(&self) -> bool {
        matches!(self, Self::CreditCard | Self::Ssn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_type_is_copy() {
        // Compile-time proof that enum is Copy (no heap allocations)
        fn assert_copy<T: Copy>() {}
        assert_copy::<PiiType>();
    }

    #[test]
    fn test_placeholders_unique() {
        let types = [
            PiiType::Email,
            PiiType::PhoneNumber,
            PiiType::Ssn,
            PiiType::CreditCard,
            PiiType::IpAddressV4,
            PiiType::IpAddressV6,
        ];
        let placeholders: Vec<_> = types.iter().map(|t| t.placeholder()).collect();
        let unique: std::collections::HashSet<_> = placeholders.iter().collect();
        assert_eq!(
            placeholders.len(),
            unique.len(),
            "Placeholders must be unique for grep-able audit logs"
        );
    }

    #[test]
    fn test_pii_type_config_round_trip() {
        let types = [
            PiiType::Email,
            PiiType::PhoneNumber,
            PiiType::Ssn,
            PiiType::CreditCard,
            PiiType::IpAddressV4,
            PiiType::IpAddressV6,
        ];
        for pii_type in &types {
            let config: PiiTypeConfig = (*pii_type).into();
            let back = config.to_pii_type().unwrap();
            assert_eq!(*pii_type, back);
        }
    }

    #[test]
    fn test_pii_type_config_serde_json() {
        let config = PiiTypeConfig::Email;
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(json, "\"email\"");

        let parsed: PiiTypeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PiiTypeConfig::Email);
    }

    #[test]
    fn test_pii_type_config_other_serde() {
        let config = PiiTypeConfig::Other("PERSON".to_string());
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(json, "{\"other\":\"PERSON\"}");

        let parsed: PiiTypeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PiiTypeConfig::Other("PERSON".to_string()));
    }

    #[test]
    fn test_pii_type_config_other_to_pii_type_returns_none() {
        let config = PiiTypeConfig::Other("PERSON".to_string());
        assert!(config.to_pii_type().is_none());
    }
}
