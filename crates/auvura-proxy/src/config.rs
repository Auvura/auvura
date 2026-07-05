use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Auvura Proxy — provider-agnostic AI security layer
#[derive(Parser, Debug)]
#[command(name = "auvura-proxy", version, about = "PII-aware AI proxy")]
pub struct Cli {
    /// Path to TOML config file
    #[arg(short, long, default_value = "auvura.toml")]
    pub config: PathBuf,

    /// Listen address (overrides config)
    #[arg(short, long)]
    pub address: Option<String>,

    /// Listen port (overrides config)
    #[arg(short, long)]
    pub port: Option<u16>,
}

/// Top-level config file structure (TOML)
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,

    #[serde(default)]
    pub policy: PolicyConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    3000
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProviderConfig {
    /// API key value (for config file — prefer api_key_env)
    #[serde(default)]
    pub api_key: Option<String>,

    /// Environment variable name containing the API key
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
}

fn default_api_key_env() -> String {
    String::new()
}

impl ProviderConfig {
    /// Resolve the API key: direct value takes precedence, then env var
    pub fn resolve_api_key(&self) -> Option<String> {
        if let Some(key) = &self.api_key {
            return Some(key.clone());
        }
        if !self.api_key_env.is_empty() {
            if let Ok(key) = std::env::var(&self.api_key_env) {
                return Some(key);
            }
        }
        None
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct PolicyConfig {
    /// Enable specific PII types (if empty, uses defaults)
    #[serde(default)]
    pub enabled_types: Vec<String>,

    /// ISO 3166-1 alpha-2 country codes for phone detection (if empty, uses defaults)
    /// Countries are tried in order; the first match wins.
    #[serde(default)]
    pub phone_countries: Option<Vec<String>>,

    /// Blocklist terms that must always be redacted
    #[serde(default)]
    pub blocklist: Vec<String>,

    /// Allowlist terms that should never be redacted
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Config {
    /// Load config from a TOML file. Missing file returns default config.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        toml::from_str(&contents).map_err(ConfigError::Parse)
    }

    /// Merge CLI overrides into the config
    pub fn merge_cli(self, cli: &Cli) -> Self {
        let mut config = self;
        if let Some(addr) = &cli.address {
            config.server.host = addr.clone();
        }
        if let Some(port) = cli.port {
            config.server.port = port;
        }
        config
    }

    /// Build the provider map from config, resolving API keys from env vars
    pub fn build_providers(&self) -> crate::ProviderMap {
        let mut providers = crate::ProviderMap::new();

        for (name, provider_cfg) in &self.providers {
            let api_key = match provider_cfg.resolve_api_key() {
                Some(key) => key,
                None => {
                    eprintln!(
                        "Warning: no API key for provider '{}', skipping",
                        name
                    );
                    continue;
                }
            };

            let adapter: Box<dyn crate::provider::ProviderAdapter> = match name.as_str() {
                "openai" => Box::new(crate::provider::OpenAIAdapter),
                "anthropic" => Box::new(crate::provider::AnthropicAdapter),
                _ => {
                    eprintln!("Warning: unknown provider '{}', skipping", name);
                    continue;
                }
            };

            providers.insert(name.clone(), (adapter, api_key));
        }

        providers
    }

    /// Build a Redactor from the policy config
    pub fn build_redactor(&self) -> auvura_core::redactor::Redactor {
        use auvura_core::{
            detectors::{
                credit_card::CreditCardDetector, email::EmailDetector,
                ip::{Ipv4Detector, Ipv6Detector}, phone_number::PhoneNumberDetector,
                ssn::SSNDetector,
            },
            policy::PolicyBuilder,
            redactor::Redactor,
            types::PiiType,
        };

        let phone_detector: Box<dyn auvura_core::detector::PiiDetector> =
            match &self.policy.phone_countries {
                Some(countries) if !countries.is_empty() => {
                    Box::new(PhoneNumberDetector::with_countries(countries.clone()))
                }
                _ => Box::new(PhoneNumberDetector::new()),
            };

        let detectors: Vec<Box<dyn auvura_core::detector::PiiDetector>> = vec![
            Box::new(EmailDetector::new()),
            phone_detector,
            Box::new(SSNDetector::new()),
            Box::new(CreditCardDetector::new()),
            Box::new(Ipv4Detector::new()),
            Box::new(Ipv6Detector::new()),
        ];

        let mut builder = PolicyBuilder::default();

        // Apply enabled types if specified
        if !self.policy.enabled_types.is_empty() {
            // Disable all first, then enable specified ones
            for pii_type in &[
                PiiType::Email,
                PiiType::PhoneNumber,
                PiiType::Ssn,
                PiiType::CreditCard,
                PiiType::IpAddressV4,
                PiiType::IpAddressV6,
            ] {
                builder = builder.disable(*pii_type);
            }
            for type_name in &self.policy.enabled_types {
                match type_name.as_str() {
                    "email" => builder = builder.enable(PiiType::Email),
                    "phone" => builder = builder.enable(PiiType::PhoneNumber),
                    "ssn" => builder = builder.enable(PiiType::Ssn),
                    "credit_card" => builder = builder.enable(PiiType::CreditCard),
                    "ipv4" => builder = builder.enable(PiiType::IpAddressV4),
                    "ipv6" => builder = builder.enable(PiiType::IpAddressV6),
                    _ => eprintln!("Warning: unknown PII type '{}', skipping", type_name),
                }
            }
        }

        if !self.policy.blocklist.is_empty() {
            let refs: Vec<&str> = self.policy.blocklist.iter().map(String::as_str).collect();
            builder = builder.with_blocklist(refs);
        }

        if !self.policy.allowlist.is_empty() {
            let refs: Vec<&str> = self.policy.allowlist.iter().map(String::as_str).collect();
            builder = builder.with_allowlist(refs);
        }

        Redactor::new(detectors, builder.build())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "failed to read config: {}", e),
            ConfigError::Parse(e) => write!(f, "failed to parse config: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 3000);
        assert!(config.providers.is_empty());
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let config = Config::load(std::path::Path::new("/nonexistent/config.toml")).unwrap();
        assert_eq!(config.server.port, 3000);
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml_str = r#"
[server]
host = "0.0.0.0"
port = 8080
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
    }

    #[test]
    fn test_parse_provider_config() {
        let toml_str = r#"
[providers.openai]
api_key_env = "OPENAI_API_KEY"

[providers.anthropic]
api_key = "sk-ant-test"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.providers.len(), 2);
        assert_eq!(
            config.providers["openai"].api_key_env,
            "OPENAI_API_KEY"
        );
        assert_eq!(
            config.providers["anthropic"].api_key,
            Some("sk-ant-test".to_string())
        );
    }

    #[test]
    fn test_parse_policy_config() {
        let toml_str = r#"
[policy]
enabled_types = ["email", "ssn"]
blocklist = ["CONFIDENTIAL"]
allowlist = ["Apple"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policy.enabled_types, vec!["email", "ssn"]);
        assert_eq!(config.policy.blocklist, vec!["CONFIDENTIAL"]);
        assert_eq!(config.policy.allowlist, vec!["Apple"]);
    }

    #[test]
    fn test_merge_cli_overrides() {
        let config = Config::default();
        let cli = Cli {
            config: PathBuf::from("auvura.toml"),
            address: Some("0.0.0.0".to_string()),
            port: Some(9090),
        };
        let merged = config.merge_cli(&cli);
        assert_eq!(merged.server.host, "0.0.0.0");
        assert_eq!(merged.server.port, 9090);
    }

    #[test]
    fn test_provider_resolve_api_key_direct() {
        let cfg = ProviderConfig {
            api_key: Some("direct-key".to_string()),
            api_key_env: String::new(),
        };
        assert_eq!(cfg.resolve_api_key(), Some("direct-key".to_string()));
    }

    #[test]
    fn test_provider_resolve_api_key_env() {
        std::env::set_var("TEST_AUVURA_KEY", "env-key");
        let cfg = ProviderConfig {
            api_key: None,
            api_key_env: "TEST_AUVURA_KEY".to_string(),
        };
        assert_eq!(cfg.resolve_api_key(), Some("env-key".to_string()));
        std::env::remove_var("TEST_AUVURA_KEY");
    }

    #[test]
    fn test_provider_resolve_api_key_missing() {
        let cfg = ProviderConfig {
            api_key: None,
            api_key_env: "NONexistent_VAR_12345".to_string(),
        };
        assert_eq!(cfg.resolve_api_key(), None);
    }

    #[test]
    fn test_parse_phone_countries() {
        let toml_str = r#"
[policy]
phone_countries = ["DE", "FR", "JP"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.policy.phone_countries,
            Some(vec!["DE".to_string(), "FR".to_string(), "JP".to_string()])
        );
    }

    #[test]
    fn test_phone_countries_defaults_to_none() {
        let toml_str = r#"
[policy]
enabled_types = ["email"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policy.phone_countries, None);
    }

    #[test]
    fn test_build_redactor_with_custom_phone_countries() {
        let toml_str = r#"
[policy]
phone_countries = ["DE"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let redactor = config.build_redactor();
        // German number should be detected
        let result = redactor.redact("DE: +49 30 12345678");
        assert_ne!(result, "DE: +49 30 12345678");
        // US local-format number with DE-only country list:
        // phonelib may or may not accept this depending on number rules,
        // so we test that intl prefix numbers still work
        let result = redactor.redact("Intl: +12025550123");
        assert_ne!(result, "Intl: +12025550123");
    }
}
