//! Auvura Proxy library — handlers, types, and test utilities

pub mod auth;
pub mod config;
pub mod provider;
pub mod rate_limit;

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
use axum::{
    extract::{Json, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use futures_util::Stream;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, info_span, Instrument};
use uuid::Uuid;

pub type ProviderMap = HashMap<String, (Box<dyn provider::ProviderAdapter>, String)>;

/// Internal fields that must NOT be forwarded to upstream provider APIs.
/// `"provider"` is Auvura routing metadata; any `_auvura_*` fields are
/// reserved for future internal use.
const INTERNAL_FIELDS: &[&str] = &["provider"];

/// Strip Auvura-internal fields from a request JSON before forwarding.
/// Removes `"provider"` and any key starting with `_auvura_`.
fn strip_internal_fields(request: &Value) -> Value {
    let Some(obj) = request.as_object() else {
        return request.clone();
    };

    let cleaned: serde_json::Map<String, Value> = obj
        .iter()
        .filter(|(key, _)| !INTERNAL_FIELDS.contains(&key.as_str()) && !key.starts_with("_auvura_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Value::Object(cleaned)
}

pub struct AppConfig {
    pub redactor: Redactor,
    pub providers: ProviderMap,
    pub http_client: Client,
    pub context_store: Arc<DashMap<String, String>>,
}

/// Stream wrapper that cleans up the context store entry when dropped.
pub struct StreamCleanup {
    inner: Pin<Box<dyn Stream<Item = Result<Event, reqwest::Error>> + Send>>,
    context_store: Arc<DashMap<String, String>>,
    session_id: String,
}

impl StreamCleanup {
    pub fn new(
        inner: impl Stream<Item = Result<Event, reqwest::Error>> + Send + 'static,
        context_store: Arc<DashMap<String, String>>,
        session_id: String,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            context_store,
            session_id,
        }
    }
}

impl Drop for StreamCleanup {
    fn drop(&mut self) {
        if !self.session_id.is_empty() {
            self.context_store.remove(&self.session_id);
        }
    }
}

impl Stream for StreamCleanup {
    type Item = Result<Event, reqwest::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Build the axum Router with all routes and optional middleware layers
pub fn app_router(
    state: Arc<AppConfig>,
    cors: Option<CorsLayer>,
    rate_limiter: Option<rate_limit::RateLimiter>,
    max_body_bytes: usize,
    auth_state: Option<auth::AuthState>,
) -> Router {
    let mut router = Router::new()
        .route("/health", get(health_check))
        .route("/v1/models", get(list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/chat/completions/stream", post(chat_completions_stream))
        .with_state(state);

    // Request body size limit
    if max_body_bytes > 0 {
        router = router.layer(RequestBodyLimitLayer::new(max_body_bytes));
    }

    // Rate limiting (per-IP via X-Forwarded-For or connecting IP)
    if let Some(limiter) = rate_limiter {
        router = router.layer(rate_limit::RateLimitLayer { limiter });
    }

    // Authentication (applied before CORS)
    if let Some(auth) = auth_state {
        router = router.layer(axum::middleware::from_fn(
            move |request: Request<axum::body::Body>, next: Next| {
                let auth_state = auth.clone();
                async move {
                    // Add auth state to request extensions
                    let mut request = request;
                    request.extensions_mut().insert(auth_state);
                    auth::auth_middleware(request, next).await
                }
            },
        ));
    }

    // Request tracing middleware
    router = router.layer(axum::middleware::from_fn(request_tracing_middleware));

    // CORS (applied last so it wraps everything)
    if let Some(cors) = cors {
        router = router.layer(cors);
    }

    router
}

/// Middleware that adds tracing spans to requests for observability.
async fn request_tracing_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let span = info_span!(
        "request",
        method = %method,
        path = %uri,
    );

    async move {
        let response = next.run(request).await;
        let status = response.status();
        info!(status = %status, "Request completed");
        response
    }
    .instrument(span)
    .await
}

/// Health check endpoint for load balancers and monitoring.
async fn health_check() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// List available models endpoint.
///
/// Returns a list of models available through the configured providers,
/// compatible with the OpenAI `/v1/models` API format.
async fn list_models(State(state): State<Arc<AppConfig>>) -> (StatusCode, Json<Value>) {
    let mut models: Vec<Value> = Vec::new();

    for (provider_name, (_adapter, _api_key)) in &state.providers {
        // Add a representative model for each configured provider
        let model = match provider_name.as_str() {
            "openai" => serde_json::json!({
                "id": "gpt-4",
                "object": "model",
                "owned_by": "openai",
                "provider": provider_name,
            }),
            "anthropic" => serde_json::json!({
                "id": "claude-3-sonnet-20240229",
                "object": "model",
                "owned_by": "anthropic",
                "provider": provider_name,
            }),
            "gemini" | "google" => serde_json::json!({
                "id": "gemini-pro",
                "object": "model",
                "owned_by": "google",
                "provider": provider_name,
            }),
            "mistral" | "mistralai" => serde_json::json!({
                "id": "mistral-large-latest",
                "object": "model",
                "owned_by": "mistral",
                "provider": provider_name,
            }),
            "cohere" => serde_json::json!({
                "id": "command-r-plus",
                "object": "model",
                "owned_by": "cohere",
                "provider": provider_name,
            }),
            "azure" | "azure_openai" => serde_json::json!({
                "id": "gpt-4",
                "object": "model",
                "owned_by": "azure-openai",
                "provider": provider_name,
            }),
            "bedrock" | "aws" => serde_json::json!({
                "id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "object": "model",
                "owned_by": "aws-bedrock",
                "provider": provider_name,
            }),
            "ollama" | "vllm" => serde_json::json!({
                "id": "llama3",
                "object": "model",
                "owned_by": "ollama",
                "provider": provider_name,
            }),
            _ => serde_json::json!({
                "id": "default",
                "object": "model",
                "owned_by": provider_name,
                "provider": provider_name,
            }),
        };
        models.push(model);
    }

    let response = serde_json::json!({
        "object": "list",
        "data": models,
    });

    (StatusCode::OK, Json(response))
}

pub async fn chat_completions(
    State(state): State<Arc<AppConfig>>,
    Json(mut request): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Token-based PII reconstruction for non-streaming responses.
    // Uses [[PII_0]], [[PII_1]] tokens instead of redacted forms,
    // which is more robust against LLM rephrasing.
    let mut token_map: HashMap<String, String> = HashMap::new();
    let mut token_counter: usize = 0;

    if let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages {
            if let Some(content) = message.get_mut("content").and_then(|c| c.as_str()) {
                let original = content.to_string();
                let redacted = state.redactor.redact(&original);

                if redacted.as_ref() != original.as_str() {
                    let token = format!("[[PII_{}]]", token_counter);
                    token_counter += 1;
                    token_map.insert(token.clone(), original);
                    message["content"] = Value::String(token);
                } else {
                    message["content"] = Value::String(redacted.into_owned());
                }
            }
        }
    }

    let provider_name = request
        .get("provider")
        .and_then(|p| p.as_str())
        .unwrap_or("openai")
        .to_lowercase();

    if let Some((adapter, api_key)) = state.providers.get(&provider_name) {
        let provider_request = adapter.translate_request(&strip_internal_fields(&request));

        let url = format!("{}/{}", adapter.base_url(), adapter.endpoint_path());
        let headers = adapter.required_headers(api_key);

        let mut req_builder = state.http_client.post(&url);
        for (key, value) in headers {
            req_builder = req_builder.header(&key, &value);
        }

        match req_builder.json(&provider_request).send().await {
            Ok(response) => {
                if let Ok(provider_response) = response.json::<Value>().await {
                    let mut standard_response = adapter.translate_response(&provider_response);

                    // Reconstruct ALL originals in the response using token mapping
                    if !token_map.is_empty() {
                        if let Some(choices) = standard_response
                            .get_mut("choices")
                            .and_then(|c| c.as_array_mut())
                        {
                            for choice in choices {
                                if let Some(message) =
                                    choice.get_mut("message").and_then(|m| m.as_object_mut())
                                {
                                    if let Some(content) =
                                        message.get_mut("content").and_then(|c| c.as_str())
                                    {
                                        let mut reconstructed = content.to_string();
                                        for (token, original) in &token_map {
                                            reconstructed =
                                                reconstructed.replace(token, original);
                                        }
                                        message["content"] = Value::String(reconstructed);
                                    }
                                }
                            }
                        }
                    }

                    (StatusCode::OK, Json(standard_response))
                } else {
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(Value::Object(serde_json::Map::from_iter(vec![(
                            "error".to_string(),
                            Value::String("Failed to parse provider response".to_string()),
                        )]))),
                    )
                }
            }
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                Json(Value::Object(serde_json::Map::from_iter(vec![(
                    "error".to_string(),
                    Value::String(format!("Provider request failed: {}", e)),
                )]))),
            ),
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(Value::Object(serde_json::Map::from_iter(vec![(
                "error".to_string(),
                Value::String(format!("Unknown provider: {}", provider_name)),
            )]))),
        )
    }
}

pub async fn chat_completions_stream(
    State(state): State<Arc<AppConfig>>,
    Json(mut request): Json<Value>,
) -> axum::response::Response {
    use futures_util::StreamExt;

    let mut token_map: HashMap<String, String> = HashMap::new();
    let mut token_counter: usize = 0;

    if let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages {
            if let Some(content) = message.get_mut("content").and_then(|c| c.as_str()) {
                let original = content.to_string();
                let redacted = state.redactor.redact(&original);

                if redacted.as_ref() != original.as_str() {
                    let token = format!("[[PII_{}]]", token_counter);
                    token_counter += 1;
                    token_map.insert(token.clone(), original);
                    message["content"] = Value::String(token);
                } else {
                    message["content"] = Value::String(redacted.into_owned());
                }
            }
        }
    }

    if !token_map.is_empty() {
        let token_list: Vec<String> = token_map
            .iter()
            .map(|(token, orig)| {
                let masked = mask_original(orig);
                format!("{} = redacted value ({})", token, masked)
            })
            .collect();

        let system_note = format!(
            "NOTE: The following tokens represent redacted sensitive information. \
             Reference these exact tokens in your response — they will be \
             reconstructed to the original values for the user.\n\n{}\n\n\
             IMPORTANT: Use the token markers (e.g., [[PII_0]]) directly in your \
             response. Do NOT attempt to write the original values.",
            token_list.join("\n")
        );

        if let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut()) {
            let system_msg = serde_json::json!({
                "role": "system",
                "content": system_note
            });
            messages.insert(0, system_msg);
        }
    }

    let session_id = if !token_map.is_empty() {
        let id = Uuid::new_v4().to_string();
        if let Ok(json) = serde_json::to_string(&token_map) {
            state.context_store.insert(id.clone(), json);
        }
        Some(id)
    } else {
        None
    };

    let provider_name = request
        .get("provider")
        .and_then(|p| p.as_str())
        .unwrap_or("openai")
        .to_lowercase();

    let Some((adapter, api_key)) = state.providers.get(&provider_name) else {
        let error_body = serde_json::json!({
            "error": format!("Unknown provider: {}", provider_name)
        });
        return (StatusCode::NOT_FOUND, Json(error_body)).into_response();
    };

    let mut provider_request = adapter.translate_request(&strip_internal_fields(&request));
    if let Some(obj) = provider_request.as_object_mut() {
        obj.insert("stream".to_string(), Value::Bool(true));
    }

    let url = format!("{}/{}", adapter.base_url(), adapter.endpoint_path());
    let headers = adapter.required_headers(api_key);

    let mut req_builder = state.http_client.post(&url);
    for (key, value) in headers {
        req_builder = req_builder.header(&key, &value);
    }

    match req_builder.json(&provider_request).send().await {
        Ok(response) => {
            // Check provider response status before streaming
            let status = response.status();
            if status.is_client_error() || status.is_server_error() {
                let error_body = serde_json::json!({
                    "error": format!("Provider returned HTTP {}", status.as_u16())
                });
                return (StatusCode::BAD_GATEWAY, Json(error_body)).into_response();
            }

            let context_store = state.context_store.clone();

            let reverse_map: HashMap<String, String> = token_map.into_iter().collect();
            let has_tokens = !reverse_map.is_empty();
            let session_id_clone = session_id.clone();

            let stream = response.bytes_stream().map(move |chunk| match chunk {
                Ok(bytes) => {
                    let mut text = String::from_utf8_lossy(&bytes).to_string();

                    if has_tokens {
                        if let Some(ref id) = session_id_clone {
                            if let Some(stored) = context_store.get(id) {
                                if let Ok(map) =
                                    serde_json::from_str::<HashMap<String, String>>(&stored)
                                {
                                    for (token, original) in &map {
                                        text = text.replace(token, original);
                                    }
                                }
                            }
                        }
                    }

                    Ok(Event::default().data(text))
                }
                Err(e) => Ok(Event::default().event("error").data(format!("{}", e))),
            });

            let cleanup_id = session_id.unwrap_or_default();
            Sse::new(StreamCleanup::new(
                stream,
                state.context_store.clone(),
                cleanup_id,
            ))
            .into_response()
        }
        Err(e) => {
            let error_body = serde_json::json!({
                "error": format!("Provider request failed: {}", e)
            });
            (StatusCode::BAD_GATEWAY, Json(error_body)).into_response()
        }
    }
}

pub fn mask_original(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    match chars.len() {
        0 => String::new(),
        1 => "*".to_string(),
        2 => format!("{}*", chars[0]),
        3 => format!("{}*{}", chars[0], chars[2]),
        _ => {
            let last = chars.len() - 1;
            format!("{}***{}", chars[0], chars[last])
        }
    }
}

/// Build a test redactor with all detectors
pub fn test_redactor() -> Redactor {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![
        Box::new(EmailDetector::new()),
        Box::new(PhoneNumberDetector::new()),
        Box::new(SSNDetector::new()),
        Box::new(CreditCardDetector::new()),
        Box::new(Ipv4Detector::new()),
        Box::new(Ipv6Detector::new()),
    ];
    Redactor::new(detectors, auvura_core::policy::RedactionPolicy::default())
}

/// Build an AppConfig with a provider pointing to the given base URL
pub fn test_config_with_url(base_url: &str) -> Arc<AppConfig> {
    use provider::FixedUrlProvider;

    let provider = FixedUrlProvider::new(base_url.to_string());
    let mut providers: ProviderMap = HashMap::new();
    providers.insert(
        "mock".to_string(),
        (Box::new(provider), "test-api-key".to_string()),
    );

    Arc::new(AppConfig {
        redactor: test_redactor(),
        providers,
        http_client: Client::new(),
        context_store: Arc::new(DashMap::new()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthState;
    use crate::provider::ProviderAdapter;

    // ===== mask_original tests =====

    #[test]
    fn test_mask_original_empty() {
        assert_eq!(mask_original(""), "");
    }

    #[test]
    fn test_mask_original_single_char() {
        assert_eq!(mask_original("a"), "*");
    }

    #[test]
    fn test_mask_original_two_chars() {
        assert_eq!(mask_original("ab"), "a*");
    }

    #[test]
    fn test_mask_original_three_chars() {
        assert_eq!(mask_original("abc"), "a*c");
    }

    #[test]
    fn test_mask_original_long_string() {
        assert_eq!(mask_original("john@example.com"), "j***m");
    }

    // ===== StreamCleanup tests =====

    #[test]
    fn test_stream_cleanup_removes_entry_on_drop() {
        let store = Arc::new(DashMap::new());
        store.insert("session-1".to_string(), "original text".to_string());

        let stream = futures_util::stream::iter(vec![]);
        let cleanup = StreamCleanup::new(stream, store.clone(), "session-1".to_string());

        assert!(store.contains_key("session-1"));
        drop(cleanup);
        assert!(!store.contains_key("session-1"));
    }

    #[test]
    fn test_stream_cleanup_empty_session_id_no_panic() {
        let store = Arc::new(DashMap::new());
        store.insert("session-1".to_string(), "original text".to_string());

        let stream = futures_util::stream::iter(vec![]);
        let cleanup = StreamCleanup::new(stream, store.clone(), "".to_string());

        drop(cleanup);
        // Entry should NOT be removed (empty session_id)
        assert!(store.contains_key("session-1"));
    }

    #[test]
    fn test_stream_cleanup_nonexistent_entry_no_panic() {
        let store = Arc::new(DashMap::new());
        let stream = futures_util::stream::iter(vec![]);
        let cleanup = StreamCleanup::new(stream, store.clone(), "nonexistent".to_string());
        drop(cleanup);
    }

    // ===== strip_internal_fields tests =====

    #[test]
    fn test_strip_internal_fields_removes_provider() {
        let request = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "provider": "openai"
        });

        let stripped = strip_internal_fields(&request);
        assert_eq!(stripped["model"], "gpt-4");
        assert!(stripped.get("provider").is_none());
        assert_eq!(stripped["messages"][0]["content"], "Hello");
    }

    #[test]
    fn test_strip_internal_fields_removes_auvura_prefix() {
        let request = serde_json::json!({
            "model": "gpt-4",
            "_auvura_session": "abc-123",
            "_auvura_trace_id": "trace-456",
            "messages": [{"role": "user", "content": "Hello"}]
        });

        let stripped = strip_internal_fields(&request);
        assert_eq!(stripped["model"], "gpt-4");
        assert!(stripped.get("_auvura_session").is_none());
        assert!(stripped.get("_auvura_trace_id").is_none());
    }

    #[test]
    fn test_strip_internal_fields_preserves_standard_fields() {
        let request = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 1024,
            "stream": true,
            "temperature": 0.7
        });

        let stripped = strip_internal_fields(&request);
        assert_eq!(stripped, request);
    }

    #[test]
    fn test_strip_internal_fields_handles_non_object() {
        let value = Value::String("not an object".to_string());
        let stripped = strip_internal_fields(&value);
        assert_eq!(stripped, value);
    }

    // ===== OpenAI adapter tests =====

    #[test]
    fn test_openai_adapter_pass_through_request() {
        let adapter = provider::OpenAIAdapter;
        let request = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}]
        });

        let result = adapter.translate_request(&request);
        assert_eq!(result, request);
    }

    #[test]
    fn test_openai_adapter_pass_through_response() {
        let adapter = provider::OpenAIAdapter;
        let response = serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "Hi!"}}]
        });

        let result = adapter.translate_response(&response);
        assert_eq!(result, response);
    }

    #[test]
    fn test_openai_adapter_base_url() {
        let adapter = provider::OpenAIAdapter;
        assert_eq!(adapter.base_url(), "https://api.openai.com/v1");
    }

    #[test]
    fn test_openai_adapter_required_headers() {
        let adapter = provider::OpenAIAdapter;
        let headers = adapter.required_headers("sk-test");

        assert_eq!(headers.get("Authorization").unwrap(), "Bearer sk-test");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
    }

    // ===== Handler integration tests =====

    #[tokio::test]
    async fn test_health_check_returns_ok() {
        let config = test_config_with_url("http://localhost:0");
        let app = app_router(config, None, None, 0, None);

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn test_list_models_returns_providers() {
        let config = test_config_with_url("http://localhost:0");
        let app = app_router(config, None, None, 0, None);

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/models")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["object"], "list");
        assert!(json["data"].is_array());
        // Should have at least one model (the mock provider)
        assert!(json["data"].as_array().unwrap().len() >= 1);
    }

    #[tokio::test]
    async fn test_list_models_empty_when_no_providers() {
        let _config = test_config_with_url("http://localhost:0");
        // Clear providers to test empty case
        let config = std::sync::Arc::new(AppConfig {
            redactor: test_redactor(),
            providers: HashMap::new(),
            http_client: Client::new(),
            context_store: std::sync::Arc::new(DashMap::new()),
        });
        let app = app_router(config, None, None, 0, None);

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/models")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["object"], "list");
        assert_eq!(json["data"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_chat_completions_unknown_provider() {
        let config = test_config_with_url("http://localhost:0");
        let app = app_router(config, None, None, 0, None);

        let request = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "provider": "nonexistent"
        });

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&request).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_some());
    }

    #[tokio::test]
    async fn test_chat_completions_mock_provider() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "Hello from mock!"}}]
            })))
            .mount(&mock_server)
            .await;

        let config = test_config_with_url(&mock_server.uri());
        let app = app_router(config, None, None, 0, None);

        let request = serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "Hi there"}],
            "provider": "mock"
        });

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&request).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["choices"][0]["message"]["content"], "Hello from mock!");
    }

    #[tokio::test]
    async fn test_pii_reconstruction_with_token_markers() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock response that echoes back the PII token (simulating LLM behavior)
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "I received your email [[PII_0]] and will respond soon."}}]
            })))
            .mount(&mock_server)
            .await;

        let config = test_config_with_url(&mock_server.uri());
        let app = app_router(config, None, None, 0, None);

        // Send message with PII - email should be tokenized
        let request = serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "Contact me at john@example.com"}],
            "provider": "mock"
        });

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&request).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // The token [[PII_0]] should be replaced with the original email
        let content = json["choices"][0]["message"]["content"].as_str().unwrap();
        assert!(content.contains("john@example.com"), "Token should be replaced with original email, got: {}", content);
        assert!(!content.contains("[[PII_0]]"), "Token marker should not remain in output, got: {}", content);
    }

    #[tokio::test]
    async fn test_stream_unknown_provider_returns_sse_error() {
        let config = test_config_with_url("http://localhost:0");
        let app = app_router(config, None, None, 0, None);

        let request = serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "Hi"}],
            "provider": "nonexistent"
        });

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions/stream")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&request).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("Unknown provider"));
    }

    #[tokio::test]
    async fn test_provider_field_stripped_from_upstream_request() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Capture the request body sent to the upstream
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "ok"}}]
            })))
            .mount(&mock_server)
            .await;

        let config = test_config_with_url(&mock_server.uri());
        let app = app_router(config, None, None, 0, None);

        let request = serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "Hi"}],
            "provider": "mock",
            "_auvura_session": "secret-session-id"
        });

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&request).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Verify via wiremock that the upstream received the request
        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);

        let upstream_body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        // "provider" must NOT be in the upstream request
        assert!(
            upstream_body.get("provider").is_none(),
            "provider field leaked to upstream"
        );
        // "_auvura_session" must NOT be in the upstream request
        assert!(
            upstream_body.get("_auvura_session").is_none(),
            "_auvura_session leaked to upstream"
        );
        // Standard fields must still be present
        assert_eq!(upstream_body["model"], "test-model");
    }

    // ===== CORS integration tests =====

    #[tokio::test]
    async fn test_cors_preflight_returns_headers() {
        use tower_http::cors::CorsLayer;

        let config = test_config_with_url("http://localhost:0");
        let cors = CorsLayer::new()
            .allow_origin(["https://app.example.com".parse().unwrap()])
            .allow_methods([axum::http::Method::POST, axum::http::Method::OPTIONS])
            .allow_headers([axum::http::header::CONTENT_TYPE]);
        let app = app_router(config, Some(cors), None, 0, None);

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("OPTIONS")
                .uri("/v1/chat/completions")
                .header("Origin", "https://app.example.com")
                .header("Access-Control-Request-Method", "POST")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let headers = response.headers();
        assert!(
            headers.contains_key("access-control-allow-origin"),
            "missing Access-Control-Allow-Origin header"
        );
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://app.example.com"
        );
    }

    #[tokio::test]
    async fn test_cors_no_layer_no_headers() {
        let config = test_config_with_url("http://localhost:0");
        let app = app_router(config, None, None, 0, None);

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("OPTIONS")
                .uri("/v1/chat/completions")
                .header("Origin", "https://app.example.com")
                .header("Access-Control-Request-Method", "POST")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        // Without CORS layer, no Access-Control headers should be present
        let headers = response.headers();
        assert!(
            !headers.contains_key("access-control-allow-origin"),
            "Access-Control-Allow-Origin should not be present without CORS config"
        );
    }

    // ===== Rate limiting integration tests =====

    #[tokio::test]
    async fn test_rate_limit_rejects_over_limit() {
        use crate::rate_limit::RateLimiter;

        let config = test_config_with_url("http://localhost:0");
        let limiter = RateLimiter::new(2, 2); // 2 req/s, burst of 2
        let app = app_router(config, None, Some(limiter), 0, None);

        let make_request = || {
            let app = app.clone();
            async move {
                tower::ServiceExt::oneshot(
                    app,
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/v1/chat/completions")
                        .header("content-type", "application/json")
                        .header("x-forwarded-for", "10.0.0.1:1234")
                        .body(axum::body::Body::from(
                            serde_json::to_vec(&serde_json::json!({
                                "model": "gpt-4",
                                "messages": [{"role": "user", "content": "Hi"}],
                                "provider": "nonexistent"
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        // First two should succeed (burst)
        let r1 = make_request().await;
        assert_ne!(r1.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

        let r2 = make_request().await;
        assert_ne!(r2.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

        // Third should be rate limited
        let r3 = make_request().await;
        assert_eq!(r3.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_rate_limit_different_ips_independent() {
        use crate::rate_limit::RateLimiter;

        let config = test_config_with_url("http://localhost:0");
        let limiter = RateLimiter::new(1, 1); // 1 req/s, burst of 1
        let app = app_router(config, None, Some(limiter), 0, None);

        let make_request = |ip: &str| {
            let app = app.clone();
            let ip = ip.to_string();
            async move {
                tower::ServiceExt::oneshot(
                    app,
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/v1/chat/completions")
                        .header("content-type", "application/json")
                        .header("x-forwarded-for", format!("{}:1234", ip))
                        .body(axum::body::Body::from(
                            serde_json::to_vec(&serde_json::json!({
                                "model": "gpt-4",
                                "messages": [{"role": "user", "content": "Hi"}],
                                "provider": "nonexistent"
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        // IP1 uses its burst
        let r1 = make_request("10.0.0.1").await;
        assert_ne!(r1.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

        // IP1 exhausted
        let r2 = make_request("10.0.0.1").await;
        assert_eq!(r2.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

        // IP2 still has its own burst
        let r3 = make_request("10.0.0.2").await;
        assert_ne!(r3.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    // ===== Request size limit integration tests =====

    #[tokio::test]
    async fn test_request_size_limit_rejects_oversized() {
        let config = test_config_with_url("http://localhost:0");
        // 100 byte limit
        let app = app_router(config, None, None, 100, None);

        // Create a request body larger than 100 bytes
        let large_body = "x".repeat(200);
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(large_body))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_request_size_limit_allows_small() {
        let config = test_config_with_url("http://localhost:0");
        // 10MB limit
        let app = app_router(config, None, None, 10 * 1024 * 1024, None);

        let small_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}],"provider":"nonexistent"}"#;
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(small_body))
                .unwrap(),
        )
        .await
        .unwrap();

        // Should not be payload too large (will be NOT_FOUND since provider doesn't exist)
        assert_ne!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_no_size_limit_when_zero() {
        let config = test_config_with_url("http://localhost:0");
        // 0 = no limit
        let app = app_router(config, None, None, 0, None);

        let large_body = "x".repeat(1000);
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(large_body))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_ne!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ===== Authentication integration tests =====

    #[tokio::test]
    async fn test_auth_rejects_no_api_key() {
        let config = test_config_with_url("http://localhost:0");
        let auth_state = AuthState::new(vec!["valid-key".to_string()]);
        let app = app_router(config, None, None, 0, Some(auth_state));

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "model": "test",
                        "messages": [{"role": "user", "content": "Hi"}],
                        "provider": "mock"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_rejects_invalid_api_key() {
        let config = test_config_with_url("http://localhost:0");
        let auth_state = AuthState::new(vec!["valid-key".to_string()]);
        let app = app_router(config, None, None, 0, Some(auth_state));

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("authorization", "Bearer invalid-key")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "model": "test",
                        "messages": [{"role": "user", "content": "Hi"}],
                        "provider": "mock"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_accepts_valid_api_key() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "Hello!"}}]
            })))
            .mount(&mock_server)
            .await;

        let config = test_config_with_url(&mock_server.uri());
        let auth_state = AuthState::new(vec!["valid-key".to_string()]);
        let app = app_router(config, None, None, 0, Some(auth_state));

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("authorization", "Bearer valid-key")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "model": "test",
                        "messages": [{"role": "user", "content": "Hi"}],
                        "provider": "mock"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_health_endpoint_always_accessible() {
        let config = test_config_with_url("http://localhost:0");
        let auth_state = AuthState::new(vec!["valid-key".to_string()]);
        let app = app_router(config, None, None, 0, Some(auth_state));

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_disabled_allows_all() {
        let config = test_config_with_url("http://localhost:0");
        let app = app_router(config, None, None, 0, None);

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_multiple_keys() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "Hello!"}}]
            })))
            .mount(&mock_server)
            .await;

        let config = test_config_with_url(&mock_server.uri());
        let auth_state = AuthState::new(vec![
            "key-1".to_string(),
            "key-2".to_string(),
            "key-3".to_string(),
        ]);
        let app = app_router(config, None, None, 0, Some(auth_state));

        // Try with second key
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("authorization", "Bearer key-2")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "model": "test",
                        "messages": [{"role": "user", "content": "Hi"}],
                        "provider": "mock"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
