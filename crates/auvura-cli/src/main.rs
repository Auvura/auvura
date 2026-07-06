use auvura_core::{
    detector::PiiDetector,
    detectors::{
        address::AddressDetector,
        credit_card::CreditCardDetector,
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
use auvura_proxy::config::Config;
use clap::{Parser, Subcommand};
use std::io::Read;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "auvura",
    version,
    about = "PII detection, redaction, and proxy management"
)]
struct Cli {
    /// Path to TOML config file
    #[arg(short, long, global = true, default_value = "auvura.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Redact PII from text and print the result
    Redact {
        /// Text to redact (if omitted, reads from stdin or --file)
        #[arg(short, long)]
        text: Option<String>,

        /// Read input from a file instead of stdin
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Output format: "text" (default) or "json"
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },

    /// Detect PII in text and report findings without redacting
    Validate {
        /// Text to validate (if omitted, reads from stdin or --file)
        #[arg(short, long)]
        text: Option<String>,

        /// Read input from a file instead of stdin
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Output format: "text" (default) or "json"
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },

    /// Start the PII-aware proxy server
    Serve {
        /// Listen address (overrides config)
        #[arg(short, long)]
        address: Option<String>,

        /// Listen port (overrides config)
        #[arg(short, long)]
        port: Option<u16>,
    },
}

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum OutputFormat {
    #[default]
    Text,
    Json,
}

fn build_detectors(config: &Config) -> Vec<Box<dyn PiiDetector>> {
    let phone_detector: Box<dyn PiiDetector> = match &config.policy.phone_countries {
        Some(countries) if !countries.is_empty() => {
            Box::new(PhoneNumberDetector::with_countries(countries.clone()))
        }
        _ => Box::new(PhoneNumberDetector::new()),
    };

    vec![
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
    ]
}

fn build_redactor(
    config: &Config,
    audit_logger: Option<impl auvura_core::audit::AuditLogger + 'static>,
) -> Redactor {
    let detectors = build_detectors(config);

    let mut builder = PolicyBuilder::default();

    if !config.policy.enabled_types.is_empty() {
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
        for type_name in &config.policy.enabled_types {
            match type_name.as_str() {
                "email" => builder = builder.enable(PiiType::Email),
                "phone" | "phone_number" => builder = builder.enable(PiiType::PhoneNumber),
                "ssn" => builder = builder.enable(PiiType::Ssn),
                "credit_card" => builder = builder.enable(PiiType::CreditCard),
                "ipv4" | "ip_address_v4" => builder = builder.enable(PiiType::IpAddressV4),
                "ipv6" | "ip_address_v6" => builder = builder.enable(PiiType::IpAddressV6),
                "iban" => builder = builder.enable(PiiType::Iban),
                "passport" | "passport_number" => builder = builder.enable(PiiType::PassportNumber),
                "national_id" => builder = builder.enable(PiiType::NationalId),
                "address" | "physical_address" => {
                    builder = builder.enable(PiiType::PhysicalAddress)
                }
                _ => eprintln!("Warning: unknown PII type '{}', skipping", type_name),
            }
        }
    }

    if !config.policy.blocklist.is_empty() {
        let refs: Vec<&str> = config.policy.blocklist.iter().map(String::as_str).collect();
        builder = builder.with_blocklist(refs);
    }

    if !config.policy.allowlist.is_empty() {
        let refs: Vec<&str> = config.policy.allowlist.iter().map(String::as_str).collect();
        builder = builder.with_allowlist(refs);
    }

    if let Some(logger) = audit_logger {
        Redactor::with_audit_logger(detectors, builder.build(), logger)
    } else {
        Redactor::new(detectors, builder.build())
    }
}

fn read_input(text: &Option<String>, file: &Option<PathBuf>) -> Result<String, String> {
    if let Some(t) = text {
        return Ok(t.clone());
    }
    if let Some(f) = file {
        return std::fs::read_to_string(f)
            .map_err(|e| format!("failed to read file '{}': {}", f.display(), e));
    }
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("failed to read stdin: {}", e))?;
    Ok(buf)
}

fn pii_type_name(pii_type: PiiType) -> &'static str {
    match pii_type {
        PiiType::Email => "email",
        PiiType::PhoneNumber => "phone",
        PiiType::Ssn => "ssn",
        PiiType::CreditCard => "credit_card",
        PiiType::IpAddressV4 => "ipv4",
        PiiType::IpAddressV6 => "ipv6",
        PiiType::Iban => "iban",
        PiiType::PassportNumber => "passport",
        PiiType::NationalId => "national_id",
        PiiType::PhysicalAddress => "address",
        PiiType::Other(name) => name,
    }
}

fn handle_redact(config: &Config, text: &str, format: &OutputFormat) {
    let redactor = build_redactor(config, None::<auvura_core::audit::NoopAuditLogger>);
    let result = redactor.redact(text);

    match format {
        OutputFormat::Text => {
            print!("{}", result);
        }
        OutputFormat::Json => {
            let detected = result.as_ref() != text;
            let output = serde_json::json!({
                "input": text,
                "redacted": result.as_ref(),
                "changed": detected,
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
    }
}

fn handle_validate(config: &Config, text: &str, format: &OutputFormat) {
    let redactor = build_redactor(config, None::<auvura_core::audit::NoopAuditLogger>);
    let detectors = build_detectors(config);

    let multi = auvura_core::detector::MultiDetector::new(detectors);
    let all_detections = multi.detect(text);

    let redacted = redactor.redact(text);
    let has_pii = !all_detections.is_empty();

    match format {
        OutputFormat::Text => {
            if all_detections.is_empty() {
                println!("No PII detected.");
            } else {
                println!("Found {} PII detection(s):", all_detections.len());
                for d in &all_detections {
                    println!(
                        "  {} at byte {}..{}: \"{}\"",
                        pii_type_name(d.pii_type),
                        d.start,
                        d.end,
                        d.original,
                    );
                }
                println!();
                println!("Redacted output:");
                println!("{}", redacted);
            }
        }
        OutputFormat::Json => {
            let findings: Vec<serde_json::Value> = all_detections
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "type": pii_type_name(d.pii_type),
                        "start": d.start,
                        "end": d.end,
                        "original": d.original,
                    })
                })
                .collect();

            let output = serde_json::json!({
                "input": text,
                "detections": findings,
                "count": all_detections.len(),
                "has_pii": has_pii,
                "redacted": redacted.as_ref(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let config = match Config::load(cli.config.as_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to load config");
            std::process::exit(1);
        }
    };

    match &cli.command {
        Commands::Redact { text, file, format } => {
            let input = match read_input(text, file) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read input");
                    std::process::exit(1);
                }
            };
            handle_redact(&config, &input, format);
        }
        Commands::Validate { text, file, format } => {
            let input = match read_input(text, file) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read input");
                    std::process::exit(1);
                }
            };
            handle_validate(&config, &input, format);
        }
        Commands::Serve { address, port } => {
            let mut config = config;
            if let Some(addr) = address {
                config.server.host = addr.clone();
            }
            if let Some(p) = port {
                config.server.port = *p;
            }

            // Set up audit logging if enabled
            let audit_logger = if config.audit.is_enabled() {
                let logger = auvura_core::audit::JsonAuditLogger::new();
                info!(
                    destination = %config.audit.destination,
                    "Audit logging enabled"
                );
                Some(logger)
            } else {
                None
            };

            let redactor = if let Some(logger) = audit_logger {
                config.build_redactor(Some(logger))
            } else {
                config.build_redactor(None::<auvura_core::audit::NoopAuditLogger>)
            };
            let providers = config.build_providers();

            if providers.is_empty() {
                warn!("No providers configured. Set API keys in config or environment.");
            }

            let app_state = std::sync::Arc::new(auvura_proxy::AppConfig {
                redactor,
                providers,
                http_client: reqwest::Client::new(),
                context_store: std::sync::Arc::new(dashmap::DashMap::new()),
            });

            let cors = config.cors.to_cors_layer();
            let rate_limiter = config.rate_limit.to_limiter();
            let max_body_bytes = config.request_limit.max_body_bytes;

            // Build auth state if enabled
            let auth_state = if config.auth.is_enabled() {
                let keys = config.auth.resolve_keys();
                if keys.is_empty() {
                    warn!("Authentication enabled but no valid API keys configured");
                    None
                } else {
                    info!(key_count = keys.len(), "Authentication enabled");
                    Some(auvura_proxy::auth::AuthState::new(keys))
                }
            } else {
                None
            };

            let app =
                auvura_proxy::app_router(app_state, cors, rate_limiter, max_body_bytes, auth_state);

            let addr: std::net::SocketAddr =
                format!("{}:{}", config.server.host, config.server.port)
                    .parse()
                    .expect("Invalid listen address");

            info!(addr = %addr, "Server starting");

            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

            // Graceful shutdown: wait for SIGTERM or SIGINT
            let shutdown_signal = async {
                let ctrl_c = tokio::signal::ctrl_c();
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .unwrap();

                tokio::select! {
                    _ = ctrl_c => {
                        info!("Received SIGINT, shutting down gracefully...");
                    }
                    _ = sigterm.recv() => {
                        info!("Received SIGTERM, shutting down gracefully...");
                    }
                }
            };

            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal)
                .await
                .unwrap();

            info!("Shutdown complete");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_read_input_from_text() {
        let result = read_input(&Some("hello".to_string()), &None).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_read_input_from_file() {
        let dir = std::env::temp_dir().join("auvura_cli_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("input.txt");
        std::fs::write(&path, "file content").unwrap();

        let result = read_input(&None, &Some(path.clone())).unwrap();
        assert_eq!(result, "file content");

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn test_read_input_missing_file_errors() {
        let result = read_input(&None, &Some(PathBuf::from("/nonexistent/file.txt")));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read file"));
    }

    #[test]
    fn test_read_input_text_takes_priority() {
        let result = read_input(
            &Some("from text".to_string()),
            &Some(PathBuf::from("/nonexistent")),
        )
        .unwrap();
        assert_eq!(result, "from text");
    }

    #[test]
    fn test_handle_redact_no_pii() {
        let config = test_config();
        handle_redact(&config, "no pii here", &OutputFormat::Text);
    }

    #[test]
    fn test_handle_redact_with_pii() {
        let config = test_config();
        handle_redact(&config, "email: test@example.com", &OutputFormat::Text);
    }

    #[test]
    fn test_handle_validate_no_pii() {
        let config = test_config();
        handle_validate(&config, "no pii here", &OutputFormat::Text);
    }

    #[test]
    fn test_handle_validate_with_pii() {
        let config = test_config();
        handle_validate(&config, "email: test@example.com", &OutputFormat::Text);
    }

    #[test]
    fn test_pii_type_name_mapping() {
        assert_eq!(pii_type_name(PiiType::Email), "email");
        assert_eq!(pii_type_name(PiiType::PhoneNumber), "phone");
        assert_eq!(pii_type_name(PiiType::Ssn), "ssn");
        assert_eq!(pii_type_name(PiiType::CreditCard), "credit_card");
        assert_eq!(pii_type_name(PiiType::IpAddressV4), "ipv4");
        assert_eq!(pii_type_name(PiiType::IpAddressV6), "ipv6");
        assert_eq!(pii_type_name(PiiType::Other("CUSTOM")), "CUSTOM");
    }

    #[test]
    fn test_build_redactor_default_config() {
        let config = test_config();
        let redactor = build_redactor(&config, None::<auvura_core::audit::NoopAuditLogger>);
        let result = redactor.redact("Contact john@example.com");
        assert_ne!(result.as_ref(), "Contact john@example.com");
    }

    #[test]
    fn test_build_redactor_with_blocklist() {
        let mut config = test_config();
        config.policy.blocklist = vec!["SECRET".to_string()];
        let redactor = build_redactor(&config, None::<auvura_core::audit::NoopAuditLogger>);
        let result = redactor.redact("This is SECRET info");
        assert!(result.contains("██████"));
    }

    #[test]
    fn test_build_redactor_with_allowlist() {
        let mut config = test_config();
        config.policy.allowlist = vec!["john@example.com".to_string()];
        let redactor = build_redactor(&config, None::<auvura_core::audit::NoopAuditLogger>);
        let result = redactor.redact("Email john@example.com");
        assert!(result.contains("john@example.com"));
    }

    #[test]
    fn test_build_redactor_disabled_type() {
        let mut config = test_config();
        config.policy.enabled_types = vec!["email".to_string()];
        let redactor = build_redactor(&config, None::<auvura_core::audit::NoopAuditLogger>);
        // Email should be detected
        let result = redactor.redact("Email: test@example.com");
        assert_ne!(result.as_ref(), "Email: test@example.com");
        // SSN should NOT be detected (only email enabled)
        let result = redactor.redact("SSN: 123-45-6789");
        assert_eq!(result.as_ref(), "SSN: 123-45-6789");
    }

    #[test]
    fn test_validate_json_output_no_pii() {
        let config = test_config();
        // Just verify it doesn't panic
        handle_validate(&config, "no pii", &OutputFormat::Json);
    }

    #[test]
    fn test_validate_json_output_with_pii() {
        let config = test_config();
        handle_validate(&config, "Email: test@example.com", &OutputFormat::Json);
    }

    #[test]
    fn test_redact_json_output() {
        let config = test_config();
        handle_redact(&config, "Email: test@example.com", &OutputFormat::Json);
    }
}
