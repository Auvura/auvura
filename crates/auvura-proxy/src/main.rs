//! Auvura Proxy - Provider-agnostic AI security layer
//!
//! Provides OpenAI-compatible endpoints that forward requests to any AI provider
//! while ensuring sensitive data never leaves the local environment.

use auvura_core::redactor::Redactor;
use axum::{
    extract::{Json, State},
    routing::post,
    Router,
};
use provider::ProviderAdapter;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio;

mod provider;

struct AppConfig {
    redactor: Redactor,
    providers: HashMap<String, (Box<dyn ProviderAdapter>, String)>,
    http_client: Client,
}

#[tokio::main]
async fn main() {
    // Load config from environment or config file
    let config = load_config();

    let app_state = Arc::new(AppConfig {
        redactor: config.redactor,
        providers: config.providers,
        http_client: Client::new(),
    });

    let app = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Auvura Proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn chat_completions(
    State(state): State<Arc<AppConfig>>,
    Json(mut request): Json<Value>,
) -> Json<Value> {
    // Step 1: Redact sensitive data in the request
    if let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages {
            if let Some(content) = message.get_mut("content").and_then(|c| c.as_str()) {
                let redacted = state.redactor.redact(content);
                message["content"] = Value::String(redacted.into_owned());
            }
        }
    }

    // Step 2: Determine which provider to use
    let provider_name = request
        .get("provider")
        .and_then(|p| p.as_str())
        .unwrap_or("openai");

    if let Some((adapter, api_key)) = state.providers.get(provider_name) {
        // Step 3: Translate request to provider format
        let provider_request = adapter.translate_request(&request);

        // Step 4: Forward to provider API
        let url = format!("{}/chat/completions", adapter.base_url());
        let headers = adapter.required_headers(api_key);

        let mut req_builder = state.http_client.post(&url);
        for (key, value) in headers {
            req_builder = req_builder.header(&key, &value);
        }

        match req_builder.json(&provider_request).send().await {
            Ok(response) => {
                if let Ok(provider_response) = response.json::<Value>().await {
                    // Step 5: Translate response back to OpenAI format
                    let standard_response = adapter.translate_response(&provider_response);
                    Json(standard_response)
                } else {
                    Json(Value::Object(serde_json::Map::from_iter(vec![
                        ("error".to_string(), Value::String("Failed to parse provider response".to_string()))
                    ])))
                }
            }
            Err(e) => Json(Value::Object(serde_json::Map::from_iter(vec![
                ("error".to_string(), Value::String(format!("Provider request failed: {}", e)))
            ]))),
        }
    } else {
        Json(Value::Object(serde_json::Map::from_iter(vec![
            ("error".to_string(), Value::String(format!("Unknown provider: {}", provider_name)))
        ])))
    }
}

struct ProxyConfig {
    redactor: Redactor,
    providers: HashMap<String, (Box<dyn ProviderAdapter>, String)>,
}

fn load_config() -> ProxyConfig {
    // Simple config for now - in production this would load from file/env
    let redactor = Redactor::new(
        vec![], // Add detectors as needed
        auvura_core::policy::RedactionPolicy::default(),
    );

    let mut providers: HashMap<String, (Box<dyn ProviderAdapter>, String)> = HashMap::new();

    // OpenAI
    if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
        providers.insert(
            "openai".to_string(),
            (Box::new(provider::OpenAIAdapter), api_key),
        );
    }

    // Anthropic
    if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
        providers.insert(
            "anthropic".to_string(),
            (Box::new(provider::AnthropicAdapter), api_key),
        );
    }

    ProxyConfig {
        redactor,
        providers,
    }
}
