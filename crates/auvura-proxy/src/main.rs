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

/// SSE streaming endpoint with token-based PII reconstruction
///
/// Strategy: Replace PII with unique token markers (e.g., `[[EMAIL_1]]`) and
/// inject a system message telling the LLM to reference these tokens. The LLM
/// echoes the tokens back, and we replace them with the originals in the stream.
///
/// For non-PII sessions, the stream passes through unchanged.
async fn chat_completions_stream(
    State(state): State<Arc<AppConfig>>,
    Json(mut request): Json<Value>,
) -> impl axum::response::IntoResponse {
    use futures_util::StreamExt;

    // token_map: token marker → original text (e.g., "[[EMAIL_1]]" → "john@example.com")
    let mut token_map: HashMap<String, String> = HashMap::new();
    let mut token_counter: usize = 0;

    if let Some(messages) = request.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages {
            if let Some(content) = message.get_mut("content").and_then(|c| c.as_str()) {
                let original = content.to_string();
                let redacted = state.redactor.redact(&original);

                if redacted.as_ref() != original.as_str() {
                    // PII found — replace with unique token markers
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

    // Inject a system message explaining the tokens to the LLM
    if !token_map.is_empty() {
        let token_list: Vec<String> = token_map
            .iter()
            .map(|(token, orig)| {
                // Show a masked version of the original (e.g., "j***@e***.com")
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
            // Insert as a system message at the beginning
            let system_msg = serde_json::json!({
                "role": "system",
                "content": system_note
            });
            messages.insert(0, system_msg);
        }
    }

    // Store token map in context store (keyed by a session ID)
    let session_id = if !token_map.is_empty() {
        let id = Uuid::new_v4().to_string();
        // Serialize token_map as JSON for storage
        if let Ok(json) = serde_json::to_string(&token_map) {
            state.context_store.insert(id.clone(), json);
        }
        Some(id)
    } else {
        None
    };

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

            // Pre-compute the reverse map for the stream closure
            // We need String → String for the closure, not &str
            let reverse_map: HashMap<String, String> = token_map.into_iter().collect();
            let has_tokens = !reverse_map.is_empty();
            let session_id_clone = session_id.clone();

            let stream = response.bytes_stream().map(move |chunk| {
                match chunk {
                    Ok(bytes) => {
                        let mut text = String::from_utf8_lossy(&bytes).to_string();

                        // Reconstruct PII by replacing token markers
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
                }
            });

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

/// Mask an original value for the system message hint.
/// Shows first/last char with asterisks in between.
fn mask_original(s: &str) -> String {
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

fn load_config() -> (Redactor, ProviderMap) {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![
        Box::new(EmailDetector::new()),
        Box::new(PhoneNumberDetector::new()),
        Box::new(SSNDetector::new()),
        Box::new(CreditCardDetector::new()),
        Box::new(Ipv4Detector::new()),
        Box::new(Ipv6Detector::new()),
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
