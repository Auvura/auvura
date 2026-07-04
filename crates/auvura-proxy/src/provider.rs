//! Provider-agnostic adapter system for AI cloud providers

use serde_json::Value;
use std::collections::HashMap;

/// Trait for provider-specific request/response translation
pub trait ProviderAdapter: Send + Sync {
    /// Translate Auvura standard request to provider format
    fn translate_request(&self, request: &Value) -> Value;

    /// Translate provider response to Auvura standard format
    fn translate_response(&self, response: &Value) -> Value;

    /// Get the provider's API base URL
    fn base_url(&self) -> &str;

    /// Get required headers for this provider
    fn required_headers(&self, api_key: &str) -> HashMap<String, String>;
}

/// OpenAI provider adapter
pub struct OpenAIAdapter;

impl ProviderAdapter for OpenAIAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        // OpenAI format is our standard, pass through
        request.clone()
    }

    fn translate_response(&self, response: &Value) -> Value {
        // OpenAI format is our standard, pass through
        response.clone()
    }

    fn base_url(&self) -> &str {
        "https://api.openai.com/v1"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers
    }
}

/// Anthropic Claude provider adapter
pub struct AnthropicAdapter;

impl ProviderAdapter for AnthropicAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        // Translate from OpenAI format to Anthropic format
        let mut anthropic_request = serde_json::Map::new();

        if let Some(model) = request.get("model") {
            anthropic_request.insert("model".to_string(), model.clone());
        }

        if let Some(messages) = request.get("messages").and_then(|m| m.as_array()) {
            // Convert OpenAI messages to Anthropic format
            if let Some(last_message) = messages.last() {
                if let Some(content) = last_message.get("content").and_then(|c| c.as_str()) {
                    anthropic_request.insert(
                        "prompt".to_string(),
                        Value::String(format!("\n\nHuman: {}\n\nAssistant:", content)),
                    );
                }
            }
        }

        if let Some(max_tokens) = request.get("max_tokens") {
            anthropic_request.insert("max_tokens_to_sample".to_string(), max_tokens.clone());
        }

        Value::Object(anthropic_request)
    }

    fn translate_response(&self, response: &Value) -> Value {
        // Translate from Anthropic format to OpenAI format
        let mut openai_response = serde_json::Map::new();

        let mut choices = Vec::new();
        if let Some(completion) = response.get("completion").and_then(|c| c.as_str()) {
            let mut choice = serde_json::Map::new();
            let mut message = serde_json::Map::new();
            message.insert("role".to_string(), Value::String("assistant".to_string()));
            message.insert("content".to_string(), Value::String(completion.to_string()));
            choice.insert("message".to_string(), Value::Object(message));
            choices.push(Value::Object(choice));
        }

        openai_response.insert("choices".to_string(), Value::Array(choices));
        Value::Object(openai_response)
    }

    fn base_url(&self) -> &str {
        "https://api.anthropic.com/v1"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), api_key.to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers
    }
}
