//! Auvura Proxy - Provider-agnostic AI security layer
//!
//! Provides OpenAI-compatible endpoints that forward requests to any AI provider
//! while ensuring sensitive data never leaves the local environment.

use auvura_core::{
    detector::PiiDetector,
    detectors::{
        credit_card::CreditCardDetector,
        email::EmailDetector,
        ip::{Ipv4Detector, Ipv6Detector},
        phone_number::PhoneNumberDetector,
        ssn::SSNDetector,
    },
    redactor::Redactor,
};
use std::net::SocketAddr;
use std::sync::Arc;

fn load_config() -> (Redactor, auvura_proxy::ProviderMap) {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![
        Box::new(EmailDetector::new()),
        Box::new(PhoneNumberDetector::new()),
        Box::new(SSNDetector::new()),
        Box::new(CreditCardDetector::new()),
        Box::new(Ipv4Detector::new()),
        Box::new(Ipv6Detector::new()),
    ];
    let redactor = Redactor::new(detectors, auvura_core::policy::RedactionPolicy::default());

    let mut providers: auvura_proxy::ProviderMap = std::collections::HashMap::new();

    if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
        providers.insert(
            "openai".to_string(),
            (Box::new(auvura_proxy::provider::OpenAIAdapter), api_key),
        );
    }

    if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
        providers.insert(
            "anthropic".to_string(),
            (Box::new(auvura_proxy::provider::AnthropicAdapter), api_key),
        );
    }

    (redactor, providers)
}

#[tokio::main]
async fn main() {
    let (redactor, providers) = load_config();

    let app_state = Arc::new(auvura_proxy::AppConfig {
        redactor,
        providers,
        http_client: reqwest::Client::new(),
        context_store: Arc::new(dashmap::DashMap::new()),
    });

    let app = auvura_proxy::app_router(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Auvura Proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
