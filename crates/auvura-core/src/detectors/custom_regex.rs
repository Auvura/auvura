//! CustomRegexDetector - User-defined regex patterns for organization-specific PII
//!
//! Allows users to define custom PII patterns via TOML configuration
//! without writing Rust code. Useful for employee IDs, case numbers,
//! project codes, and other organization-specific identifiers.

use crate::{
    detector::{Detection, PiiDetector},
    types::PiiType,
};
use regex::Regex;
use std::sync::Arc;

/// Configuration for a custom regex detector
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomRegexConfig {
    /// Name/label for this detector (e.g., "employee_id", "case_number")
    pub name: String,
    /// Regex pattern to match
    pub pattern: String,
    /// Redaction placeholder (e.g., "[EMP_ID]", "[CASE_NUM]")
    #[serde(default = "default_placeholder")]
    pub placeholder: String,
    /// Confidence level: "high", "medium", or "low"
    #[serde(default = "default_confidence")]
    pub confidence: String,
    /// Optional regex flags (e.g., "i" for case-insensitive)
    #[serde(default)]
    pub flags: Option<String>,
}

fn default_placeholder() -> String {
    "[REDACTED]".to_string()
}

fn default_confidence() -> String {
    "medium".to_string()
}

/// Custom regex detector that matches user-defined patterns
pub struct CustomRegexDetector {
    /// Leaked static string for PiiType::Other
    name_static: &'static str,
    pattern: Arc<Regex>,
    placeholder: String,
    confidence_level: crate::detector::Confidence,
}

impl CustomRegexDetector {
    /// Create a new custom regex detector from configuration
    pub fn from_config(config: &CustomRegexConfig) -> Result<Self, String> {
        // Build pattern with optional flags
        let pattern_str = if let Some(flags) = &config.flags {
            format!("(?{}){}", flags, config.pattern)
        } else {
            config.pattern.clone()
        };

        let pattern = Regex::new(&pattern_str)
            .map_err(|e| format!("Invalid regex pattern '{}': {}", config.pattern, e))?;

        let confidence_level = match config.confidence.to_lowercase().as_str() {
            "high" => crate::detector::Confidence::High,
            "low" => crate::detector::Confidence::Low,
            _ => crate::detector::Confidence::Medium,
        };

        // Leak the name string to get a 'static str for PiiType::Other
        // This is acceptable because detectors are long-lived and few in number
        let name_static: &'static str = Box::leak(config.name.clone().into_boxed_str());

        Ok(Self {
            name_static,
            pattern: Arc::new(pattern),
            placeholder: config.placeholder.clone(),
            confidence_level,
        })
    }

    /// Get the redaction placeholder for this detector
    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }

    /// Get the detector name
    pub fn name(&self) -> &str {
        self.name_static
    }
}

impl PiiDetector for CustomRegexDetector {
    fn pii_type(&self) -> PiiType {
        PiiType::Other(self.name_static)
    }

    fn confidence(&self) -> crate::detector::Confidence {
        self.confidence_level
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        self.pattern
            .find_iter(text)
            .map(|m| Detection {
                pii_type: self.pii_type(),
                confidence: self.confidence_level,
                start: m.start(),
                end: m.end(),
                original: m.as_str().to_string(),
            })
            .collect()
    }

    fn anchor_patterns(&self) -> Vec<&'static str> {
        // Custom detectors don't have fixed anchors
        Vec::new()
    }
}

/// Batch create custom detectors from a list of configurations
pub fn build_custom_detectors(
    configs: &[CustomRegexConfig],
) -> (Vec<Box<dyn PiiDetector>>, Vec<String>) {
    let mut detectors: Vec<Box<dyn PiiDetector>> = Vec::new();
    let mut errors = Vec::new();

    for config in configs {
        match CustomRegexDetector::from_config(config) {
            Ok(detector) => {
                detectors.push(Box::new(detector));
            }
            Err(e) => {
                errors.push(e);
            }
        }
    }

    (detectors, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_regex_employee_id() {
        let config = CustomRegexConfig {
            name: "employee_id".to_string(),
            pattern: r"EMP\d{6}".to_string(),
            placeholder: "[EMP_ID]".to_string(),
            confidence: "high".to_string(),
            flags: None,
        };

        let detector = CustomRegexDetector::from_config(&config).unwrap();
        let text = "Contact employee EMP123456 for assistance";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "EMP123456");
        assert_eq!(detections[0].start, 17);
        assert_eq!(detections[0].end, 26);
    }

    #[test]
    fn test_custom_regex_case_insensitive() {
        let config = CustomRegexConfig {
            name: "case_number".to_string(),
            pattern: r"CASE-\d{4}-\d{4}".to_string(),
            placeholder: "[CASE]".to_string(),
            confidence: "medium".to_string(),
            flags: Some("i".to_string()),
        };

        let detector = CustomRegexDetector::from_config(&config).unwrap();
        let text = "Reference case-2024-0001 and CASE-2024-0002";
        let detections = detector.detect(text);

        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].original, "case-2024-0001");
        assert_eq!(detections[1].original, "CASE-2024-0002");
    }

    #[test]
    fn test_custom_regex_invalid_pattern() {
        let config = CustomRegexConfig {
            name: "invalid".to_string(),
            pattern: r"[invalid".to_string(), // Missing closing bracket
            placeholder: "[REDacted]".to_string(),
            confidence: "medium".to_string(),
            flags: None,
        };

        let result = CustomRegexDetector::from_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_custom_detectors_batch() {
        let configs = vec![
            CustomRegexConfig {
                name: "emp_id".to_string(),
                pattern: r"EMP\d{6}".to_string(),
                placeholder: "[EMP]".to_string(),
                confidence: "high".to_string(),
                flags: None,
            },
            CustomRegexConfig {
                name: "invalid".to_string(),
                pattern: r"[bad".to_string(),
                placeholder: "[BAD]".to_string(),
                confidence: "medium".to_string(),
                flags: None,
            },
        ];

        let (detectors, errors) = build_custom_detectors(&configs);
        assert_eq!(detectors.len(), 1);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Invalid regex"));
    }

    #[test]
    fn test_custom_regex_placeholder() {
        let config = CustomRegexConfig {
            name: "project_code".to_string(),
            pattern: r"PRJ-[A-Z]{3}-\d{3}".to_string(),
            placeholder: "[PROJECT]".to_string(),
            confidence: "low".to_string(),
            flags: None,
        };

        let detector = CustomRegexDetector::from_config(&config).unwrap();
        assert_eq!(detector.placeholder(), "[PROJECT]");
        assert_eq!(detector.name(), "project_code");
    }

    #[test]
    fn test_custom_regex_with_redactor() {
        use crate::{policy::RedactionPolicy, redactor::Redactor, types::PiiType};

        let config = CustomRegexConfig {
            name: "ssn_like".to_string(),
            pattern: r"\d{3}-\d{2}-\d{4}".to_string(),
            placeholder: "[SSN]".to_string(),
            confidence: "high".to_string(),
            flags: None,
        };

        let detector = CustomRegexDetector::from_config(&config).unwrap();

        // First, verify detection works
        let detections = detector.detect("SSN: 123-45-6789");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].original, "123-45-6789");
        assert_eq!(detections[0].pii_type, PiiType::Other("ssn_like"));

        // Create a policy with custom placeholder and enable the custom type
        let policy = RedactionPolicy::builder()
            .enable(PiiType::Other("ssn_like"))
            .with_placeholder(PiiType::Other("ssn_like"), "[SSN]")
            .build();
        let redactor = Redactor::new(vec![Box::new(detector)], policy);

        let input = "SSN: 123-45-6789";
        let result = redactor.redact(input);
        assert_eq!(result, "SSN: [SSN]");
    }
}
