//! Auvura Proxy - Provider-agnostic AI security layer
//!
//! Provides OpenAI-compatible endpoints that forward requests to any AI provider
//! while ensuring sensitive data never leaves the local environment.

use auvura_proxy::config::{Cli, Config};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

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
        Ok(c) => c.merge_cli(&cli),
        Err(e) => {
            tracing::error!(error = %e, "Failed to load config");
            std::process::exit(1);
        }
    };

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

    let app_state = Arc::new(auvura_proxy::AppConfig {
        redactor,
        providers,
        http_client: reqwest::Client::new(),
        context_store: Arc::new(dashmap::DashMap::new()),
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

    let app = auvura_proxy::app_router(
        app_state,
        cors,
        rate_limiter,
        max_body_bytes,
        auth_state,
        Some(Arc::new(auvura_proxy::metrics::MetricsState::new())),
    );

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid listen address");

    info!(addr = %addr, "Server starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    // Graceful shutdown: wait for SIGTERM or SIGINT
    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();

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
