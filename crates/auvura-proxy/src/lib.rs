//! Auvura Proxy library — handlers, types, and test utilities

pub mod provider;

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
    extract::{Json, State},
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    routing::post,
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
        .filter(|(key, _)| {
            !INTERNAL_FIELDS.contains(&key.as_str()) && !key.starts_with("_auvura_")
        })
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

/// Build the axum Router with all routes
pub fn app_router(state: Arc<AppConfig>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/chat/completions/stream", post(chat_completions_stream))
        .with_state(state)
}

pub async fn chat_completions(
    State(state): State<Arc<AppConfig>>,
    Json(mut request): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Collect ALL originals from messages containing PII
    let mut originals: Vec<String> = Vec::new();

    if let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages {
            if let Some(content) = message.get_mut("content").and_then(|c| c.as_str()) {
                let original = content.to_string();
                let redacted = state.redactor.redact(&original);

                if redacted.as_ref() != original.as_str() {
                    originals.push(original.clone());
                    message["content"] = Value::String(redacted.into_owned());
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

                    // Reconstruct ALL originals in the response
                    if !originals.is_empty() {
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
                                        for original in &originals {
                                            let redacted_form: String = state
                                                .redactor
                                                .redact(original.as_str())
                                                .into_owned();
                                            reconstructed =
                                                reconstructed.replace(&redacted_form, original);
                                        }
                                        message["content"] = Value::String(reconstructed);
                                    }
                                }
                            }
                        }
                    }

                    (StatusCode::OK, Json(standard_response))
                } else {
                    (StatusCode::BAD_GATEWAY, Json(Value::Object(serde_json::Map::from_iter(vec![(
                        "error".to_string(),
                        Value::String("Failed to parse provider response".to_string()),
                    )]))))
                }
            }
            Err(e) => (StatusCode::BAD_GATEWAY, Json(Value::Object(serde_json::Map::from_iter(vec![(
                "error".to_string(),
                Value::String(format!("Provider request failed: {}", e)),
            )])))),
        }
    } else {
        (StatusCode::NOT_FOUND, Json(Value::Object(serde_json::Map::from_iter(vec![(
            "error".to_string(),
            Value::String(format!("Unknown provider: {}", provider_name)),
        )]))))
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
    async fn test_chat_completions_unknown_provider() {
        let config = test_config_with_url("http://localhost:0");
        let app = app_router(config);

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
        let app = app_router(config);

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
    async fn test_stream_unknown_provider_returns_sse_error() {
        let config = test_config_with_url("http://localhost:0");
        let app = app_router(config);

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
        let app = app_router(config);

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

        let upstream_body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).unwrap();
        // "provider" must NOT be in the upstream request
        assert!(upstream_body.get("provider").is_none(), "provider field leaked to upstream");
        // "_auvura_session" must NOT be in the upstream request
        assert!(upstream_body.get("_auvura_session").is_none(), "_auvura_session leaked to upstream");
        // Standard fields must still be present
        assert_eq!(upstream_body["model"], "test-model");
    }
}
