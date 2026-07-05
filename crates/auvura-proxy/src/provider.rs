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

    /// Get the endpoint path relative to base_url (e.g., "chat/completions" or "messages")
    fn endpoint_path(&self) -> &str {
        "chat/completions"
    }

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

/// Anthropic Claude provider adapter (Messages API)
pub struct AnthropicAdapter;

impl ProviderAdapter for AnthropicAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        let mut anthropic_request = serde_json::Map::new();

        // Model
        if let Some(model) = request.get("model") {
            anthropic_request.insert("model".to_string(), model.clone());
        }

        // Max tokens (Messages API uses "max_tokens", not "max_tokens_to_sample")
        if let Some(max_tokens) = request.get("max_tokens") {
            anthropic_request.insert("max_tokens".to_string(), max_tokens.clone());
        } else {
            // Anthropic requires max_tokens; default to 4096 if not provided
            anthropic_request.insert("max_tokens".to_string(), Value::Number(4096.into()));
        }

        // System message → top-level "system" field (Messages API format)
        let mut messages = Vec::new();
        if let Some(input_messages) = request.get("messages").and_then(|m| m.as_array()) {
            for msg in input_messages {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");

                if role == "system" {
                    // Anthropic takes system as a top-level field
                    anthropic_request
                        .insert("system".to_string(), Value::String(content.to_string()));
                } else {
                    // User/assistant messages → messages array
                    messages.push(serde_json::json!({
                        "role": role,
                        "content": content
                    }));
                }
            }
        }

        anthropic_request.insert("messages".to_string(), Value::Array(messages));

        // Stream flag (Messages API also uses "stream": true)
        if let Some(stream) = request.get("stream") {
            anthropic_request.insert("stream".to_string(), stream.clone());
        }

        Value::Object(anthropic_request)
    }

    fn translate_response(&self, response: &Value) -> Value {
        // Translate from Anthropic Messages API format to OpenAI format
        let mut openai_response = serde_json::Map::new();

        let mut choices = Vec::new();

        // Messages API: response["content"] is an array of content blocks
        if let Some(content_blocks) = response.get("content").and_then(|c| c.as_array()) {
            // Concatenate all text blocks
            let full_text: String = content_blocks
                .iter()
                .filter_map(|block| {
                    if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                        block.get("text").and_then(|t| t.as_str()).map(String::from)
                    } else {
                        None
                    }
                })
                .collect();

            let mut choice = serde_json::Map::new();
            let mut message = serde_json::Map::new();
            message.insert("role".to_string(), Value::String("assistant".to_string()));
            message.insert("content".to_string(), Value::String(full_text));
            choice.insert("message".to_string(), Value::Object(message));

            // Map stop_reason → finish_reason
            if let Some(stop_reason) = response.get("stop_reason") {
                let finish_reason = match stop_reason.as_str() {
                    Some("end_turn") => "stop",
                    Some("max_tokens") => "length",
                    Some("stop_sequence") => "stop",
                    _ => "stop",
                };
                choice.insert(
                    "finish_reason".to_string(),
                    Value::String(finish_reason.to_string()),
                );
            }

            choices.push(Value::Object(choice));
        }

        openai_response.insert("choices".to_string(), Value::Array(choices));
        Value::Object(openai_response)
    }

    fn base_url(&self) -> &str {
        "https://api.anthropic.com/v1"
    }

    fn endpoint_path(&self) -> &str {
        "messages"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), api_key.to_string());
        headers.insert("anthropic-version".to_string(), "2023-06-01".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_translate_request_messages_api() {
        let adapter = AnthropicAdapter;
        let request = serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello!"}
            ],
            "max_tokens": 1024
        });

        let result = adapter.translate_request(&request);

        assert_eq!(result["model"], "claude-3-sonnet-20240229");
        assert_eq!(result["max_tokens"], 1024);
        assert_eq!(result["system"], "You are a helpful assistant.");
        assert_eq!(result["messages"][0]["role"], "user");
        assert_eq!(result["messages"][0]["content"], "Hello!");
        assert!(result.get("prompt").is_none());
        assert!(result.get("max_tokens_to_sample").is_none());
    }

    #[test]
    fn test_anthropic_translate_request_defaults_max_tokens() {
        let adapter = AnthropicAdapter;
        let request = serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ]
        });

        let result = adapter.translate_request(&request);
        assert_eq!(result["max_tokens"], 4096);
    }

    #[test]
    fn test_anthropic_translate_response_messages_api() {
        let adapter = AnthropicAdapter;
        let response = serde_json::json!({
            "content": [
                {"type": "text", "text": "Hello! How can I help?"}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 8}
        });

        let result = adapter.translate_response(&response);

        assert_eq!(result["choices"][0]["message"]["role"], "assistant");
        assert_eq!(
            result["choices"][0]["message"]["content"],
            "Hello! How can I help?"
        );
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn test_anthropic_translate_response_max_tokens_stop() {
        let adapter = AnthropicAdapter;
        let response = serde_json::json!({
            "content": [
                {"type": "text", "text": "Partial response..."}
            ],
            "stop_reason": "max_tokens"
        });

        let result = adapter.translate_response(&response);
        assert_eq!(result["choices"][0]["finish_reason"], "length");
    }

    #[test]
    fn test_anthropic_endpoint_path() {
        let adapter = AnthropicAdapter;
        assert_eq!(adapter.endpoint_path(), "messages");
    }

    #[test]
    fn test_openai_endpoint_path_default() {
        let adapter = OpenAIAdapter;
        assert_eq!(adapter.endpoint_path(), "chat/completions");
    }

    #[test]
    fn test_anthropic_required_headers() {
        let adapter = AnthropicAdapter;
        let headers = adapter.required_headers("test-key");

        assert_eq!(headers.get("x-api-key").unwrap(), "test-key");
        assert_eq!(headers.get("anthropic-version").unwrap(), "2023-06-01");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
    }
}
