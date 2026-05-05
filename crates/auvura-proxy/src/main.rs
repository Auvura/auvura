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
use dashmap::DashMap;
use provider::ProviderAdapter;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio;
use uuid::Uuid;

mod provider;

type AppState = Arc<AppConfig>;

struct AppConfig {
    redactor: Redactor,
    providers: HashMap<String, (Box<dyn ProviderAdapter>, String)>,
    http_client: Client,
    context_store: Arc<DashMap<String, String>>, // UUID -> Original value
}

#[tokio::main]
async fn main() {
    // Load config from environment or config file
    let config = load_config();

    let app_state = Arc::new(AppConfig {
        redactor: config.redactor,
        providers: config.providers,
        http_client: Client::new(),
        context_store: Arc::new(DashMap::new()), // Initialize context store
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
    // Step 1: Redact sensitive data and store context (UUID -> original)
    let mut session_id = None;
    if let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages {
            if let Some(content) = message.get_mut("content").and_then(|c| c.as_str()) {
                let original = content.to_string();
                let redacted = state.redactor.redact(&original);
                
                // Store mapping for reconstruction
                if redacted.as_ref() != original.as_str() {
                    let id = Uuid::new_v4().to_string();
                    state.context_store.insert(id.clone(), original.clone());
                    session_id = Some(id);
                    message["content"] = Value::String(redacted.into_owned());
                } else {
                    message["content"] = Value::String(redacted.into_owned());
                }
            }
        }
    }

    // Step 2: Determine which provider to use
    let provider_name = request
        .get("provider")
        .and_then(|p| p.as_str())
        .unwrap_or("openai")
        .to_lowercase();

    eprintln!("[Proxy] Using provider: {}", provider_name);
    eprintln!("[Proxy] Available providers: {:?}", state.providers.keys());

    if let Some((adapter, api_key)) = state.providers.get(&provider_name) {
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
                    let mut standard_response = adapter.translate_response(&provider_response);
                    
                    // Step 6: Reconstruct original values from context store
                    if let Some(id) = &session_id {
                        if let Some(original) = state.context_store.get(id) {
                            if let Some(choices) = standard_response
                                .get_mut("choices")
                                .and_then(|c| c.as_array_mut()) 
                            {
                                for choice in choices {
                                    if let Some(message) = choice
                                        .get_mut("message")
                                        .and_then(|m| m.as_object_mut()) 
                                    {
                                        if let Some(content) = message
                                            .get_mut("content")
                                            .and_then(|c| c.as_str()) 
                                        {
                                            // Reconstruct: replace redacted form with original
                                            let redacted_form: String = 
                                                state.redactor.redact(original.as_str()).into_owned();
                                            let reconstructed = content.replace(
                                                &redacted_form,
                                                original.as_str()
                                            );
                                            message["content"] = Value::String(reconstructed);
                                        }
                                    }
                                }
                            }
                            // Clean up context store after use
                            state.context_store.remove(id);
                        }
                    }
                    
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

fn load_config() -> AppConfig {
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

    AppConfig {
        redactor,
        providers,
        http_client: Client::new(),
        context_store: Arc::new(DashMap::new()),
    }
}
