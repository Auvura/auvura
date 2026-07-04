//! Auvura Proxy - Provider-agnostic AI security layer
//!
//! Provides OpenAI-compatible endpoints that forward requests to any AI provider
//! while ensuring sensitive data never leaves the local environment.

use auvura_core::{
    detector::PiiDetector,
    detectors::{
        credit_card::CreditCardDetector, email::EmailDetector, phone_number::PhoneNumberDetector,
        ssn::SSNDetector,
    },
    redactor::Redactor,
};
use axum::{
    extract::{Json, State},
    response::sse::{Event, Sse},
    routing::post,
    Router,
};
use dashmap::DashMap;
use futures_util::Stream;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use uuid::Uuid;

mod provider;

type ProviderMap = HashMap<String, (Box<dyn provider::ProviderAdapter>, String)>;

struct AppConfig {
    redactor: Redactor,
    providers: ProviderMap,
    http_client: Client,
    context_store: Arc<DashMap<String, String>>,
}

/// Stream wrapper that cleans up the context store entry when dropped.
///
/// When a streaming response completes (or is cancelled), the `Drop` impl
/// removes the session's original-text mapping from the shared `DashMap`,
/// preventing unbounded memory growth.
struct StreamCleanup {
    inner: Pin<Box<dyn Stream<Item = Result<Event, reqwest::Error>> + Send>>,
    context_store: Arc<DashMap<String, String>>,
    session_id: String,
}

impl StreamCleanup {
    fn new(
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

#[tokio::main]
async fn main() {
    let (redactor, providers) = load_config();

    let app_state = Arc::new(AppConfig {
        redactor,
        providers,
        http_client: Client::new(),
        context_store: Arc::new(DashMap::new()),
    });

    let app = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/chat/completions/stream", post(chat_completions_stream))
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
                                    if let Some(message) =
                                        choice.get_mut("message").and_then(|m| m.as_object_mut())
                                    {
                                        if let Some(content) =
                                            message.get_mut("content").and_then(|c| c.as_str())
                                        {
                                            // Reconstruct: replace redacted form with original
                                            let redacted_form: String = state
                                                .redactor
                                                .redact(original.as_str())
                                                .into_owned();
                                            let reconstructed =
                                                content.replace(&redacted_form, original.as_str());
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
                    Json(Value::Object(serde_json::Map::from_iter(vec![(
                        "error".to_string(),
                        Value::String("Failed to parse provider response".to_string()),
                    )])))
                }
            }
            Err(e) => Json(Value::Object(serde_json::Map::from_iter(vec![(
                "error".to_string(),
                Value::String(format!("Provider request failed: {}", e)),
            )]))),
        }
    } else {
        Json(Value::Object(serde_json::Map::from_iter(vec![(
            "error".to_string(),
            Value::String(format!("Unknown provider: {}", provider_name)),
        )])))
    }
}

/// SSE streaming endpoint with chunk buffering for placeholder reconstruction
async fn chat_completions_stream(
    State(state): State<Arc<AppConfig>>,
    Json(mut request): Json<Value>,
) -> impl axum::response::IntoResponse {
    use futures_util::StreamExt;

    // Redact PII and collect (session_id, original_text, redacted_form) for reconstruction
    let mut session_id = None;
    let mut original_text = None;
    let mut redacted_form = None;

    if let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages {
            if let Some(content) = message.get_mut("content").and_then(|c| c.as_str()) {
                let original = content.to_string();
                let redacted = state.redactor.redact(&original);

                if redacted.as_ref() != original.as_str() {
                    let id = Uuid::new_v4().to_string();
                    state.context_store.insert(id.clone(), original.clone());
                    redacted_form = Some(redacted.into_owned());
                    original_text = Some(original);
                    session_id = Some(id);
                    break;
                } else {
                    message["content"] = Value::String(redacted.into_owned());
                }
            }
        }
    }

    // Inject session ID into the request after the mutable borrow is released
    if let Some(id) = &session_id {
        request["_auvura_session"] = Value::String(id.clone());
    }

    // Determine provider
    let provider_name = request
        .get("provider")
        .and_then(|p| p.as_str())
        .unwrap_or("openai")
        .to_lowercase();

    let Some((adapter, api_key)) = state.providers.get(&provider_name) else {
        let error_msg = format!("Unknown provider: {}", provider_name);
        let stream = futures_util::stream::iter(vec![Ok(Event::default().data(error_msg))]);
        return Sse::new(StreamCleanup::new(
            stream,
            state.context_store.clone(),
            "".into(),
        ));
    };

    let mut provider_request = adapter.translate_request(&request);
    if let Some(obj) = provider_request.as_object_mut() {
        obj.insert("stream".to_string(), Value::Bool(true));
    }

    let url = format!("{}/chat/completions", adapter.base_url());
    let headers = adapter.required_headers(api_key);

    let mut req_builder = state.http_client.post(&url);
    for (key, value) in headers {
        req_builder = req_builder.header(&key, &value);
    }

    match req_builder.json(&provider_request).send().await {
        Ok(response) => {
            let context_store = state.context_store.clone();

            // Pre-compute values for the stream closure
            let has_pii = session_id.is_some();
            let session_id_clone = session_id.clone();
            let redacted_form_str = redacted_form.clone();
            let original_text_str = original_text.clone();

            let stream = response.bytes_stream().map(move |chunk| {
                match chunk {
                    Ok(bytes) => {
                        let mut text = String::from_utf8_lossy(&bytes).to_string();

                        // Reconstruct PII if this session had redacted content
                        if has_pii {
                            if let (Some(id), Some(ref form), Some(ref orig)) =
                                (&session_id_clone, &redacted_form_str, &original_text_str)
                            {
                                if context_store.get(id).is_some() {
                                    text = text.replace(form, orig);
                                }
                            }
                        }

                        Ok(Event::default().data(text))
                    }
                    Err(e) => Ok(Event::default().event("error").data(format!("{}", e))),
                }
            });

            // Wrap with cleanup guard — context store entry is removed when stream is dropped
            let cleanup_id = session_id.unwrap_or_default();
            Sse::new(StreamCleanup::new(
                stream,
                state.context_store.clone(),
                cleanup_id,
            ))
        }
        Err(e) => {
            let error_msg = format!("Provider request failed: {}", e);
            let stream = futures_util::stream::iter(vec![Ok(Event::default().data(error_msg))]);
            Sse::new(StreamCleanup::new(
                stream,
                state.context_store.clone(),
                "".into(),
            ))
        }
    }
}

fn load_config() -> (Redactor, ProviderMap) {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![
        Box::new(EmailDetector::new()),
        Box::new(PhoneNumberDetector::new()),
        Box::new(SSNDetector::new()),
        Box::new(CreditCardDetector::new()),
    ];
    let redactor = Redactor::new(detectors, auvura_core::policy::RedactionPolicy::default());

    let mut providers: ProviderMap = HashMap::new();

    if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
        providers.insert(
            "openai".to_string(),
            (Box::new(provider::OpenAIAdapter), api_key),
        );
    }

    if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
        providers.insert(
            "anthropic".to_string(),
            (Box::new(provider::AnthropicAdapter), api_key),
        );
    }

    (redactor, providers)
}
