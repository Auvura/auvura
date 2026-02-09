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
    Ssn,           // US Social Security Number
    CreditCard,
    IpAddressV4,
    IpAddressV6,
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
        assert_eq!(placeholders.len(), unique.len(),
            "Placeholders must be unique for grep-able audit logs");
    }
}
