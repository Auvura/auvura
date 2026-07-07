use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, Any};

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

    #[serde(default)]
    pub cors: CorsConfig,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    #[serde(default)]
    pub request_limit: RequestLimitConfig,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(default)]
    pub audit: AuditConfig,
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

    /// Global redaction mode: "mask", "replace", "hash", or "tokenize"
    #[serde(default)]
    pub mode: Option<String>,

    /// Custom regex patterns for organization-specific PII
    #[serde(default)]
    pub custom_patterns: Vec<auvura_core::detectors::custom_regex::CustomRegexConfig>,
}

/// CORS configuration for browser-based SDK integrations.
/// When omitted or empty, CORS is disabled (no Access-Control headers sent).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CorsConfig {
    /// Allowed origins (e.g., ["https://app.example.com"]).
    /// Use ["*"] to allow all origins (not recommended for production).
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Allowed HTTP methods (e.g., ["GET", "POST", "OPTIONS"]).
    /// Defaults to ["POST", "OPTIONS"] if empty.
    #[serde(default)]
    pub allowed_methods: Vec<String>,

    /// Allowed request headers (e.g., ["Content-Type", "Authorization"]).
    /// Defaults to ["Content-Type", "Authorization"] if empty.
    #[serde(default)]
    pub allowed_headers: Vec<String>,

    /// Whether to allow credentials (cookies, auth headers).
    #[serde(default)]
    pub allow_credentials: bool,

    /// Maximum age for preflight cache in seconds.
    /// Defaults to 3600 (1 hour) if None.
    #[serde(default)]
    pub max_age: Option<u64>,
}

impl CorsConfig {
    /// Returns true if CORS is configured (at least one origin is set).
    pub fn is_enabled(&self) -> bool {
        !self.allowed_origins.is_empty()
    }

    /// Build a CorsLayer from this config.
    pub fn to_cors_layer(&self) -> Option<tower_http::cors::CorsLayer> {
        if !self.is_enabled() {
            return None;
        }

        let mut cors = tower_http::cors::CorsLayer::new();

        // Origins
        if self.allowed_origins.iter().any(|o| o == "*") {
            cors = cors.allow_origin(Any);
        } else {
            let origins: Vec<_> = self
                .allowed_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            if !origins.is_empty() {
                cors = cors.allow_origin(AllowOrigin::list(origins));
            }
        }

        // Methods
        if self.allowed_methods.is_empty() {
            cors = cors.allow_methods([axum::http::Method::POST, axum::http::Method::OPTIONS]);
        } else {
            let methods: Vec<_> = self
                .allowed_methods
                .iter()
                .filter_map(|m| m.parse().ok())
                .collect();
            cors = cors.allow_methods(methods);
        }

        // Headers
        if self.allowed_headers.is_empty() {
            cors = cors.allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
            ]);
        } else {
            let headers: Vec<_> = self
                .allowed_headers
                .iter()
                .filter_map(|h| h.parse().ok())
                .collect();
            cors = cors.allow_headers(headers);
        }

        // Credentials
        if self.allow_credentials {
            cors = cors.allow_credentials(true);
        }

        // Max age
        if let Some(seconds) = self.max_age {
            cors = cors.max_age(Duration::from_secs(seconds));
        }

        Some(cors)
    }
}

/// Rate limiting configuration to protect against abuse.
/// When omitted or disabled, no rate limiting is applied.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RateLimitConfig {
    /// Maximum requests per second per IP. None disables rate limiting.
    #[serde(default)]
    pub requests_per_second: Option<u64>,

    /// Burst capacity (max concurrent requests allowed in a burst).
    /// Defaults to requests_per_second if None.
    #[serde(default)]
    pub burst_size: Option<u64>,
}

impl RateLimitConfig {
    /// Returns true if rate limiting is configured.
    pub fn is_enabled(&self) -> bool {
        self.requests_per_second.unwrap_or(0) > 0
    }

    /// Build a rate limiter from this config.
    /// Returns None if rate limiting is disabled.
    pub fn to_limiter(&self) -> Option<crate::rate_limit::RateLimiter> {
        let rps = self.requests_per_second?;
        if rps == 0 {
            return None;
        }
        let burst = self.burst_size.unwrap_or(rps);
        Some(crate::rate_limit::RateLimiter::new(rps, burst))
    }
}

/// Request size limit configuration.
/// When omitted, defaults to 10 MB.
#[derive(Debug, Deserialize, Clone)]
pub struct RequestLimitConfig {
    /// Maximum request body size in bytes. Defaults to 10 MB.
    /// Set to 0 to disable size limits.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

impl Default for RequestLimitConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: default_max_body_bytes(),
        }
    }
}

fn default_max_body_bytes() -> usize {
    10 * 1024 * 1024 // 10 MB
}

/// Authentication configuration for the proxy.
/// When omitted or disabled, no authentication is required.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthConfig {
    /// Enable authentication. Defaults to false.
    #[serde(default)]
    pub enabled: bool,

    /// API keys that are allowed to access the proxy.
    /// Keys can be literal values or environment variable references.
    #[serde(default)]
    pub api_keys: Vec<AuthApiKey>,
}

/// An API key configuration entry.
#[derive(Debug, Deserialize, Clone)]
pub struct AuthApiKey {
    /// Literal API key value (for config file — prefer env)
    #[serde(default)]
    pub value: Option<String>,

    /// Environment variable name containing the API key
    #[serde(default)]
    pub env: Option<String>,
}

impl AuthApiKey {
    /// Resolve the API key: direct value takes precedence, then env var
    pub fn resolve(&self) -> Option<String> {
        if let Some(val) = &self.value {
            return Some(val.clone());
        }
        if let Some(env_name) = &self.env {
            if let Ok(val) = std::env::var(env_name) {
                return Some(val);
            }
        }
        None
    }
}

impl AuthConfig {
    /// Returns true if authentication is configured and enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.api_keys.is_empty()
    }

    /// Resolve all configured API keys into their values.
    /// Returns only keys that could be successfully resolved.
    pub fn resolve_keys(&self) -> Vec<String> {
        self.api_keys.iter().filter_map(|k| k.resolve()).collect()
    }
}

/// Audit logging configuration for GDPR/HIPAA compliance.
/// When enabled, detection and redaction events are logged.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuditConfig {
    /// Enable audit logging. Defaults to false.
    #[serde(default)]
    pub enabled: bool,

    /// Log destination. "stdout" (default) or "file".
    #[serde(default = "default_audit_destination")]
    pub destination: String,

    /// File path for audit logs (only used when destination is "file").
    #[serde(default)]
    pub file_path: Option<String>,
}

fn default_audit_destination() -> String {
    "stdout".to_string()
}

impl AuditConfig {
    /// Returns true if audit logging is configured and enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
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
                    eprintln!("Warning: no API key for provider '{}', skipping", name);
                    continue;
                }
            };

            let adapter: Box<dyn crate::provider::ProviderAdapter> = match name.as_str() {
                "openai" => Box::new(crate::provider::OpenAIAdapter),
                "anthropic" => Box::new(crate::provider::AnthropicAdapter),
                "gemini" | "google" => Box::new(crate::provider::GeminiAdapter),
                "mistral" | "mistralai" => Box::new(crate::provider::MistralAdapter),
                "cohere" => Box::new(crate::provider::CohereAdapter),
                "azure" | "azure_openai" => Box::new(crate::provider::AzureOpenAIAdapter::new(
                    String::new(),
                    String::new(),
                    "2024-02-01".to_string(),
                )),
                "bedrock" | "aws" => Box::new(crate::provider::AWSBedrockAdapter::new(
                    String::new(),
                    String::new(),
                )),
                "ollama" | "vllm" => Box::new(crate::provider::OllamaAdapter),
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
    ///
    /// If `audit_logger` is provided, the redactor will log detection and
    /// redaction events for GDPR/HIPAA compliance.
    pub fn build_redactor(
        &self,
        audit_logger: Option<impl auvura_core::audit::AuditLogger + 'static>,
    ) -> auvura_core::redactor::Redactor {
        use auvura_core::{
            detectors::{
                address::AddressDetector,
                credit_card::CreditCardDetector,
                custom_regex::build_custom_detectors,
                email::EmailDetector,
                iban::IbanDetector,
                ip::{Ipv4Detector, Ipv6Detector},
                national_id::NationalIdDetector,
                passport::PassportDetector,
                phone_number::PhoneNumberDetector,
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

        let mut detectors: Vec<Box<dyn auvura_core::detector::PiiDetector>> = vec![
            Box::new(EmailDetector::new()),
            phone_detector,
            Box::new(SSNDetector::new()),
            Box::new(CreditCardDetector::new()),
            Box::new(Ipv4Detector::new()),
            Box::new(Ipv6Detector::new()),
            Box::new(IbanDetector::new()),
            Box::new(PassportDetector::new()),
            Box::new(NationalIdDetector::new()),
            Box::new(AddressDetector::new()),
        ];

        // Add custom regex detectors
        if !self.policy.custom_patterns.is_empty() {
            let (custom_detectors, errors) = build_custom_detectors(&self.policy.custom_patterns);
            for error in errors {
                eprintln!("Warning: {}", error);
            }
            detectors.extend(custom_detectors);
        }

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
                PiiType::Iban,
                PiiType::PassportNumber,
                PiiType::NationalId,
                PiiType::PhysicalAddress,
            ] {
                builder = builder.disable(*pii_type);
            }
            for type_name in &self.policy.enabled_types {
                match type_name.as_str() {
                    "email" => builder = builder.enable(PiiType::Email),
                    "phone" | "phone_number" => builder = builder.enable(PiiType::PhoneNumber),
                    "ssn" => builder = builder.enable(PiiType::Ssn),
                    "credit_card" => builder = builder.enable(PiiType::CreditCard),
                    "ipv4" | "ip_address_v4" => builder = builder.enable(PiiType::IpAddressV4),
                    "ipv6" | "ip_address_v6" => builder = builder.enable(PiiType::IpAddressV6),
                    "iban" => builder = builder.enable(PiiType::Iban),
                    "passport" | "passport_number" => {
                        builder = builder.enable(PiiType::PassportNumber)
                    }
                    "national_id" => builder = builder.enable(PiiType::NationalId),
                    "address" | "physical_address" => {
                        builder = builder.enable(PiiType::PhysicalAddress)
                    }
                    // Custom types are always enabled (they're added as detectors)
                    _ => {
                        // Check if it matches a custom pattern name
                        if self.policy.custom_patterns.iter().any(|p| p.name == *type_name) {
                            // Custom types are always enabled
                        } else {
                            eprintln!("Warning: unknown PII type '{}', skipping", type_name);
                        }
                    }
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

        // Apply redaction mode if specified
        if let Some(mode_str) = &self.policy.mode {
            use auvura_core::policy::RedactionMode;
            let mode = match mode_str.as_str() {
                "replace" => RedactionMode::Replace,
                "hash" => RedactionMode::Hash,
                "tokenize" => RedactionMode::Tokenize,
                "mask" | "" => RedactionMode::Mask,
                _ => {
                    eprintln!("Warning: unknown redaction mode '{}', using default", mode_str);
                    RedactionMode::Mask
                }
            };
            builder = builder.with_mode(mode);
        }

        if let Some(audit_logger) = audit_logger {
            Redactor::with_audit_logger(detectors, builder.build(), audit_logger)
        } else {
            Redactor::new(detectors, builder.build())
        }
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
        assert_eq!(config.providers["openai"].api_key_env, "OPENAI_API_KEY");
        assert_eq!(
            config.providers["anthropic"].api_key,
            Some("sk-ant-test".to_string())
        );
    }

    #[test]
    fn test_parse_all_providers() {
        let toml_str = r#"
[providers.openai]
api_key_env = "OPENAI_API_KEY"

[providers.anthropic]
api_key = "sk-ant-test"

[providers.gemini]
api_key_env = "GEMINI_API_KEY"

[providers.mistral]
api_key_env = "MISTRAL_API_KEY"

[providers.cohere]
api_key_env = "COHERE_API_KEY"

[providers.azure]
api_key_env = "AZURE_API_KEY"

[providers.bedrock]
api_key_env = "AWS_API_KEY"

[providers.ollama]
api_key = ""
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.providers.len(), 8);
        assert_eq!(config.providers["gemini"].api_key_env, "GEMINI_API_KEY");
        assert_eq!(config.providers["mistral"].api_key_env, "MISTRAL_API_KEY");
        assert_eq!(config.providers["cohere"].api_key_env, "COHERE_API_KEY");
        assert_eq!(config.providers["azure"].api_key_env, "AZURE_API_KEY");
        assert_eq!(config.providers["bedrock"].api_key_env, "AWS_API_KEY");
        assert_eq!(config.providers["ollama"].api_key, Some(String::new()));
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
        let redactor = config.build_redactor(None::<auvura_core::audit::NoopAuditLogger>);
        // German number should be detected
        let result = redactor.redact("DE: +49 30 12345678");
        assert_ne!(result, "DE: +49 30 12345678");
        // US local-format number with DE-only country list:
        // phonelib may or may not accept this depending on number rules,
        // so we test that intl prefix numbers still work
        let result = redactor.redact("Intl: +12025550123");
        assert_ne!(result, "Intl: +12025550123");
    }

    #[test]
    fn test_parse_cors_config() {
        let toml_str = r#"
[cors]
allowed_origins = ["https://app.example.com", "https://admin.example.com"]
allowed_methods = ["POST", "OPTIONS"]
allowed_headers = ["Content-Type", "Authorization"]
allow_credentials = true
max_age = 7200
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.cors.is_enabled());
        assert_eq!(config.cors.allowed_origins.len(), 2);
        assert_eq!(config.cors.allowed_methods, vec!["POST", "OPTIONS"]);
        assert_eq!(
            config.cors.allowed_headers,
            vec!["Content-Type", "Authorization"]
        );
        assert!(config.cors.allow_credentials);
        assert_eq!(config.cors.max_age, Some(7200));
    }

    #[test]
    fn test_cors_disabled_by_default() {
        let config = Config::default();
        assert!(!config.cors.is_enabled());
        assert!(config.cors.to_cors_layer().is_none());
    }

    #[test]
    fn test_cors_wildcard_origin() {
        let toml_str = r#"
[cors]
allowed_origins = ["*"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.cors.is_enabled());
        assert!(config.cors.to_cors_layer().is_some());
    }

    #[test]
    fn test_cors_empty_origins_disabled() {
        let toml_str = r#"
[cors]
allowed_methods = ["POST"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(!config.cors.is_enabled());
        assert!(config.cors.to_cors_layer().is_none());
    }

    #[test]
    fn test_parse_rate_limit_config() {
        let toml_str = r#"
[rate_limit]
requests_per_second = 10
burst_size = 20
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.rate_limit.is_enabled());
        assert_eq!(config.rate_limit.requests_per_second, Some(10));
        assert_eq!(config.rate_limit.burst_size, Some(20));
        assert!(config.rate_limit.to_limiter().is_some());
    }

    #[test]
    fn test_rate_limit_disabled_by_default() {
        let config = Config::default();
        assert!(!config.rate_limit.is_enabled());
        assert!(config.rate_limit.to_limiter().is_none());
    }

    #[test]
    fn test_rate_limit_zero_rps_disabled() {
        let toml_str = r#"
[rate_limit]
requests_per_second = 0
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(!config.rate_limit.is_enabled());
        assert!(config.rate_limit.to_limiter().is_none());
    }

    #[test]
    fn test_parse_request_limit_config() {
        let toml_str = r#"
[request_limit]
max_body_bytes = 1048576
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.request_limit.max_body_bytes, 1048576);
    }

    #[test]
    fn test_request_limit_defaults_to_10mb() {
        let config = Config::default();
        assert_eq!(config.request_limit.max_body_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn test_request_limit_zero_disables() {
        let toml_str = r#"
[request_limit]
max_body_bytes = 0
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.request_limit.max_body_bytes, 0);
    }

    #[test]
    fn test_parse_auth_config_disabled_by_default() {
        let config = Config::default();
        assert!(!config.auth.enabled);
        assert!(config.auth.api_keys.is_empty());
        assert!(!config.auth.is_enabled());
    }

    #[test]
    fn test_parse_auth_config_enabled() {
        let toml_str = r#"
[auth]
enabled = true

[[auth.api_keys]]
value = "secret-key-1"

[[auth.api_keys]]
env = "MY_API_KEY"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.auth.enabled);
        assert_eq!(config.auth.api_keys.len(), 2);
        assert!(config.auth.is_enabled());
    }

    #[test]
    fn test_auth_config_enabled_but_no_keys() {
        let toml_str = r#"
[auth]
enabled = true
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.auth.enabled);
        assert!(config.auth.api_keys.is_empty());
        // Enabled but no keys means not actually enabled
        assert!(!config.auth.is_enabled());
    }

    #[test]
    fn test_auth_api_key_resolve_value() {
        let key = AuthApiKey {
            value: Some("direct-key".to_string()),
            env: None,
        };
        assert_eq!(key.resolve(), Some("direct-key".to_string()));
    }

    #[test]
    fn test_auth_api_key_resolve_env() {
        std::env::set_var("TEST_AUTH_KEY", "env-key");
        let key = AuthApiKey {
            value: None,
            env: Some("TEST_AUTH_KEY".to_string()),
        };
        assert_eq!(key.resolve(), Some("env-key".to_string()));
        std::env::remove_var("TEST_AUTH_KEY");
    }

    #[test]
    fn test_auth_api_key_resolve_missing_env() {
        let key = AuthApiKey {
            value: None,
            env: Some("NONEXISTENT_VAR_12345".to_string()),
        };
        assert_eq!(key.resolve(), None);
    }

    #[test]
    fn test_auth_resolve_keys() {
        std::env::set_var("TEST_AUTH_KEY_2", "env-key-2");
        let auth = AuthConfig {
            enabled: true,
            api_keys: vec![
                AuthApiKey {
                    value: Some("direct-key".to_string()),
                    env: None,
                },
                AuthApiKey {
                    value: None,
                    env: Some("TEST_AUTH_KEY_2".to_string()),
                },
                AuthApiKey {
                    value: None,
                    env: Some("NONEXISTENT_VAR".to_string()),
                },
            ],
        };
        let keys = auth.resolve_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"direct-key".to_string()));
        assert!(keys.contains(&"env-key-2".to_string()));
        std::env::remove_var("TEST_AUTH_KEY_2");
    }
}
