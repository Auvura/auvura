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
        request.clone()
    }

    fn translate_response(&self, response: &Value) -> Value {
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

        if let Some(model) = request.get("model") {
            anthropic_request.insert("model".to_string(), model.clone());
        }

        if let Some(max_tokens) = request.get("max_tokens") {
            anthropic_request.insert("max_tokens".to_string(), max_tokens.clone());
        } else {
            anthropic_request.insert("max_tokens".to_string(), Value::Number(4096.into()));
        }

        let mut messages = Vec::new();
        if let Some(input_messages) = request.get("messages").and_then(|m| m.as_array()) {
            for msg in input_messages {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");

                if role == "system" {
                    anthropic_request
                        .insert("system".to_string(), Value::String(content.to_string()));
                } else {
                    messages.push(serde_json::json!({
                        "role": role,
                        "content": content
                    }));
                }
            }
        }

        anthropic_request.insert("messages".to_string(), Value::Array(messages));

        if let Some(stream) = request.get("stream") {
            anthropic_request.insert("stream".to_string(), stream.clone());
        }

        Value::Object(anthropic_request)
    }

    fn translate_response(&self, response: &Value) -> Value {
        let mut openai_response = serde_json::Map::new();
        let mut choices = Vec::new();

        if let Some(content_blocks) = response.get("content").and_then(|c| c.as_array()) {
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

/// Google Gemini provider adapter
pub struct GeminiAdapter;

impl ProviderAdapter for GeminiAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        let mut gemini_request = serde_json::Map::new();

        if let Some(model) = request.get("model") {
            gemini_request.insert("model".to_string(), model.clone());
        }

        let mut contents = Vec::new();
        if let Some(messages) = request.get("messages").and_then(|m| m.as_array()) {
            for msg in messages {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");

                // Skip system messages - they'll be handled separately in systemInstruction
                if role == "system" {
                    continue;
                }

                contents.push(serde_json::json!({
                    "role": role,
                    "parts": [{"text": content}]
                }));
            }
        }

        gemini_request.insert("contents".to_string(), Value::Array(contents));

        let mut generation_config = serde_json::Map::new();

        if let Some(max_tokens) = request.get("max_tokens") {
            generation_config.insert("maxOutputTokens".to_string(), max_tokens.clone());
        }

        if let Some(temperature) = request.get("temperature") {
            generation_config.insert("temperature".to_string(), temperature.clone());
        }

        if let Some(top_p) = request.get("top_p") {
            generation_config.insert("topP".to_string(), top_p.clone());
        }

        if !generation_config.is_empty() {
            gemini_request.insert(
                "generationConfig".to_string(),
                Value::Object(generation_config),
            );
        }

        if let Some(messages) = request.get("messages").and_then(|m| m.as_array()) {
            if let Some(system_msg) = messages.iter().find(|m| {
                m.get("role")
                    .and_then(|r| r.as_str())
                    .map(|r| r == "system")
                    .unwrap_or(false)
            }) {
                let system_content = system_msg
                    .get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                gemini_request.insert(
                    "systemInstruction".to_string(),
                    serde_json::json!({
                        "parts": [{"text": system_content}]
                    }),
                );
            }
        }

        Value::Object(gemini_request)
    }

    fn translate_response(&self, response: &Value) -> Value {
        let mut openai_response = serde_json::Map::new();
        let mut choices = Vec::new();

        if let Some(candidates) = response.get("candidates").and_then(|c| c.as_array()) {
            for candidate in candidates {
                let mut choice = serde_json::Map::new();
                let mut message = serde_json::Map::new();

                message.insert("role".to_string(), Value::String("assistant".to_string()));

                if let Some(content) = candidate.get("content") {
                    if let Some(parts) = content.get("parts").and_then(|p| p.as_array()) {
                        let full_text: String = parts
                            .iter()
                            .filter_map(|part| {
                                part.get("text").and_then(|t| t.as_str()).map(String::from)
                            })
                            .collect();
                        message.insert("content".to_string(), Value::String(full_text));
                    }
                }

                choice.insert("message".to_string(), Value::Object(message));

                if let Some(finish_reason) = candidate.get("finishReason") {
                    let openai_reason = match finish_reason.as_str() {
                        Some("STOP") => "stop",
                        Some("MAX_TOKENS") => "length",
                        _ => "stop",
                    };
                    choice.insert(
                        "finish_reason".to_string(),
                        Value::String(openai_reason.to_string()),
                    );
                }

                choices.push(Value::Object(choice));
            }
        }

        openai_response.insert("choices".to_string(), Value::Array(choices));

        if let Some(usage_metadata) = response.get("usageMetadata") {
            let mut usage = serde_json::Map::new();
            if let Some(prompt_tokens) = usage_metadata.get("promptTokenCount") {
                usage.insert("prompt_tokens".to_string(), prompt_tokens.clone());
            }
            if let Some(completion_tokens) = usage_metadata.get("candidatesTokenCount") {
                usage.insert("completion_tokens".to_string(), completion_tokens.clone());
            }
            if let Some(total_tokens) = usage_metadata.get("totalTokenCount") {
                usage.insert("total_tokens".to_string(), total_tokens.clone());
            }
            openai_response.insert("usage".to_string(), Value::Object(usage));
        }

        Value::Object(openai_response)
    }

    fn base_url(&self) -> &str {
        "https://generativelanguage.googleapis.com/v1beta"
    }

    fn endpoint_path(&self) -> &str {
        "models/{model}:generateContent"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("x-goog-api-key".to_string(), api_key.to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers
    }
}

/// Mistral provider adapter (OpenAI-compatible with minor differences)
pub struct MistralAdapter;

impl ProviderAdapter for MistralAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        let mut mistral_request = request.clone();

        if let Some(obj) = mistral_request.as_object_mut() {
            if !obj.contains_key("max_tokens") {
                obj.insert("max_tokens".to_string(), Value::Number(4096.into()));
            }
        }

        mistral_request
    }

    fn translate_response(&self, response: &Value) -> Value {
        response.clone()
    }

    fn base_url(&self) -> &str {
        "https://api.mistral.ai/v1"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers
    }
}

/// Cohere provider adapter
pub struct CohereAdapter;

impl ProviderAdapter for CohereAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        let mut cohere_request = serde_json::Map::new();

        if let Some(model) = request.get("model") {
            cohere_request.insert("model".to_string(), model.clone());
        }

        if let Some(messages) = request.get("messages").and_then(|m| m.as_array()) {
            let prompt: String = messages
                .iter()
                .map(|msg| {
                    let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                    let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
                    format!("{}: {}", role, content)
                })
                .collect::<Vec<_>>()
                .join("\n\n");

            cohere_request.insert("message".to_string(), Value::String(prompt));
        }

        if let Some(max_tokens) = request.get("max_tokens") {
            cohere_request.insert("max_tokens".to_string(), max_tokens.clone());
        }

        if let Some(temperature) = request.get("temperature") {
            cohere_request.insert("temperature".to_string(), temperature.clone());
        }

        if let Some(top_p) = request.get("top_p") {
            cohere_request.insert("p".to_string(), top_p.clone());
        }

        Value::Object(cohere_request)
    }

    fn translate_response(&self, response: &Value) -> Value {
        let mut openai_response = serde_json::Map::new();
        let mut choices = Vec::new();

        if let Some(message) = response.get("message") {
            let mut choice = serde_json::Map::new();
            let mut openai_message = serde_json::Map::new();

            openai_message.insert("role".to_string(), Value::String("assistant".to_string()));

            if let Some(content) = message.get("content") {
                if let Some(text) = content.get("text").and_then(|t| t.as_str()) {
                    openai_message.insert("content".to_string(), Value::String(text.to_string()));
                }
            }

            choice.insert("message".to_string(), Value::Object(openai_message));

            if let Some(stop_reason) = response.get("stop_reason") {
                let openai_reason = match stop_reason.as_str() {
                    Some("END_TURN") => "stop",
                    Some("MAX_TOKENS") => "length",
                    _ => "stop",
                };
                choice.insert(
                    "finish_reason".to_string(),
                    Value::String(openai_reason.to_string()),
                );
            }

            choices.push(Value::Object(choice));
        }

        openai_response.insert("choices".to_string(), Value::Array(choices));
        Value::Object(openai_response)
    }

    fn base_url(&self) -> &str {
        "https://api.cohere.com/v1"
    }

    fn endpoint_path(&self) -> &str {
        "chat"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());
        headers
    }
}

/// Azure OpenAI provider adapter
pub struct AzureOpenAIAdapter {
    pub resource_name: String,
    pub deployment_id: String,
    pub api_version: String,
}

impl AzureOpenAIAdapter {
    pub fn new(resource_name: String, deployment_id: String, api_version: String) -> Self {
        Self {
            resource_name,
            deployment_id,
            api_version,
        }
    }
}

impl ProviderAdapter for AzureOpenAIAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        let mut azure_request = request.clone();

        if let Some(obj) = azure_request.as_object_mut() {
            if !obj.contains_key("max_tokens") {
                obj.insert("max_tokens".to_string(), Value::Number(4096.into()));
            }
        }

        azure_request
    }

    fn translate_response(&self, response: &Value) -> Value {
        response.clone()
    }

    fn base_url(&self) -> &str {
        "https://PLACEHOLDER.openai.azure.com"
    }

    fn endpoint_path(&self) -> &str {
        "openai/deployments/{deployment_id}/chat/completions"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("api-key".to_string(), api_key.to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("api-version".to_string(), self.api_version.clone());
        headers
    }
}

/// AWS Bedrock provider adapter
pub struct AWSBedrockAdapter {
    pub region: String,
    pub model_id: String,
}

impl AWSBedrockAdapter {
    pub fn new(region: String, model_id: String) -> Self {
        Self { region, model_id }
    }
}

impl ProviderAdapter for AWSBedrockAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        let mut bedrock_request = serde_json::Map::new();

        if let Some(messages) = request.get("messages").and_then(|m| m.as_array()) {
            let mut bedrock_messages = Vec::new();

            for msg in messages {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");

                if role == "system" {
                    bedrock_request
                        .insert("system".to_string(), Value::String(content.to_string()));
                } else {
                    bedrock_messages.push(serde_json::json!({
                        "role": role,
                        "content": [{"type": "text", "text": content}]
                    }));
                }
            }

            bedrock_request.insert("messages".to_string(), Value::Array(bedrock_messages));
        }

        if let Some(max_tokens) = request.get("max_tokens") {
            bedrock_request.insert("max_tokens".to_string(), max_tokens.clone());
        } else {
            bedrock_request.insert("max_tokens".to_string(), Value::Number(4096.into()));
        }

        if let Some(temperature) = request.get("temperature") {
            bedrock_request.insert("temperature".to_string(), temperature.clone());
        }

        if let Some(top_p) = request.get("top_p") {
            bedrock_request.insert("top_p".to_string(), top_p.clone());
        }

        Value::Object(bedrock_request)
    }

    fn translate_response(&self, response: &Value) -> Value {
        let mut openai_response = serde_json::Map::new();
        let mut choices = Vec::new();

        if let Some(content_blocks) = response.get("content").and_then(|c| c.as_array()) {
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

            if let Some(stop_reason) = response.get("stop_reason") {
                let finish_reason = match stop_reason.as_str() {
                    Some("end_turn") => "stop",
                    Some("max_tokens") => "length",
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
        "https://bedrock-runtime.{region}.amazonaws.com"
    }

    fn endpoint_path(&self) -> &str {
        "model/{model_id}/invoke"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert(
            "X-Amz-Target".to_string(),
            "BedrockRuntime.InvokeModel".to_string(),
        );
        headers
    }
}

/// Ollama provider adapter (local inference, OpenAI-compatible)
pub struct OllamaAdapter;

impl ProviderAdapter for OllamaAdapter {
    fn translate_request(&self, request: &Value) -> Value {
        let mut ollama_request = request.clone();

        if let Some(obj) = ollama_request.as_object_mut() {
            if !obj.contains_key("max_tokens") {
                obj.insert("max_tokens".to_string(), Value::Number(4096.into()));
            }
        }

        ollama_request
    }

    fn translate_response(&self, response: &Value) -> Value {
        response.clone()
    }

    fn base_url(&self) -> &str {
        "http://localhost:11434/v1"
    }

    fn required_headers(&self, api_key: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        if !api_key.is_empty() {
            headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
        }
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers
    }
}

/// Mock provider for testing — returns a fixed response
pub struct MockProvider {
    response: Value,
}

impl MockProvider {
    pub fn new(response: Value) -> Self {
        Self { response }
    }
}

impl ProviderAdapter for MockProvider {
    fn translate_request(&self, request: &Value) -> Value {
        request.clone()
    }

    fn translate_response(&self, _response: &Value) -> Value {
        self.response.clone()
    }

    fn base_url(&self) -> &str {
        "http://localhost:0"
    }

    fn required_headers(&self, _api_key: &str) -> HashMap<String, String> {
        HashMap::new()
    }
}

/// Test provider that passes through to a configurable base URL
pub struct FixedUrlProvider {
    base_url: String,
}

impl FixedUrlProvider {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

impl ProviderAdapter for FixedUrlProvider {
    fn translate_request(&self, request: &Value) -> Value {
        request.clone()
    }

    fn translate_response(&self, response: &Value) -> Value {
        response.clone()
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn required_headers(&self, _api_key: &str) -> HashMap<String, String> {
        HashMap::new()
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

    #[test]
    fn test_gemini_translate_request_basic() {
        let adapter = GeminiAdapter;
        let request = serde_json::json!({
            "model": "gemini-pro",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ],
            "max_tokens": 100,
            "temperature": 0.7
        });

        let result = adapter.translate_request(&request);

        assert_eq!(result["model"], "gemini-pro");
        assert!(result.get("contents").is_some());
        assert!(result.get("generationConfig").is_some());
        assert_eq!(result["generationConfig"]["maxOutputTokens"], 100);
        assert_eq!(result["generationConfig"]["temperature"], 0.7);
    }

    #[test]
    fn test_gemini_translate_request_system_message() {
        let adapter = GeminiAdapter;
        let request = serde_json::json!({
            "model": "gemini-pro",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello!"}
            ]
        });

        let result = adapter.translate_request(&request);

        assert_eq!(
            result["systemInstruction"]["parts"][0]["text"],
            "You are a helpful assistant."
        );

        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["role"], "user");
    }

    #[test]
    fn test_gemini_translate_response_basic() {
        let adapter = GeminiAdapter;
        let response = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello! How can I help?"}],
                    "role": "model"
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 8,
                "totalTokenCount": 18
            }
        });

        let result = adapter.translate_response(&response);

        assert_eq!(result["choices"][0]["message"]["role"], "assistant");
        assert_eq!(
            result["choices"][0]["message"]["content"],
            "Hello! How can I help?"
        );
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
        assert_eq!(result["usage"]["prompt_tokens"], 10);
        assert_eq!(result["usage"]["completion_tokens"], 8);
        assert_eq!(result["usage"]["total_tokens"], 18);
    }

    #[test]
    fn test_gemini_translate_response_max_tokens() {
        let adapter = GeminiAdapter;
        let response = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [{"text": "Partial response..."}],
                    "role": "model"
                },
                "finishReason": "MAX_TOKENS"
            }]
        });

        let result = adapter.translate_response(&response);
        assert_eq!(result["choices"][0]["finish_reason"], "length");
    }

    #[test]
    fn test_gemini_base_url() {
        let adapter = GeminiAdapter;
        assert_eq!(
            adapter.base_url(),
            "https://generativelanguage.googleapis.com/v1beta"
        );
    }

    #[test]
    fn test_gemini_endpoint_path() {
        let adapter = GeminiAdapter;
        assert_eq!(adapter.endpoint_path(), "models/{model}:generateContent");
    }

    #[test]
    fn test_gemini_required_headers() {
        let adapter = GeminiAdapter;
        let headers = adapter.required_headers("test-key");

        assert_eq!(headers.get("x-goog-api-key").unwrap(), "test-key");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn test_mistral_translate_request() {
        let adapter = MistralAdapter;
        let request = serde_json::json!({
            "model": "mistral-large-latest",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ]
        });

        let result = adapter.translate_request(&request);

        assert_eq!(result["model"], "mistral-large-latest");
        assert!(result.get("messages").is_some());
        assert_eq!(result["max_tokens"], 4096);
    }

    #[test]
    fn test_mistral_translate_response() {
        let adapter = MistralAdapter;
        let response = serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "Hi!"}}]
        });

        let result = adapter.translate_response(&response);
        assert_eq!(result, response);
    }

    #[test]
    fn test_mistral_base_url() {
        let adapter = MistralAdapter;
        assert_eq!(adapter.base_url(), "https://api.mistral.ai/v1");
    }

    #[test]
    fn test_mistral_required_headers() {
        let adapter = MistralAdapter;
        let headers = adapter.required_headers("test-key");

        assert_eq!(headers.get("Authorization").unwrap(), "Bearer test-key");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn test_cohere_translate_request() {
        let adapter = CohereAdapter;
        let request = serde_json::json!({
            "model": "command-r-plus",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello!"}
            ],
            "max_tokens": 100,
            "temperature": 0.7
        });

        let result = adapter.translate_request(&request);

        assert_eq!(result["model"], "command-r-plus");
        assert!(result.get("message").is_some());
        assert_eq!(result["max_tokens"], 100);
        assert_eq!(result["temperature"], 0.7);
    }

    #[test]
    fn test_cohere_translate_response() {
        let adapter = CohereAdapter;
        let response = serde_json::json!({
            "message": {
                "role": "assistant",
                "content": {"text": "Hello! How can I help?"}
            },
            "stop_reason": "END_TURN"
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
    fn test_cohere_base_url() {
        let adapter = CohereAdapter;
        assert_eq!(adapter.base_url(), "https://api.cohere.com/v1");
    }

    #[test]
    fn test_cohere_endpoint_path() {
        let adapter = CohereAdapter;
        assert_eq!(adapter.endpoint_path(), "chat");
    }

    #[test]
    fn test_ollama_adapter() {
        let adapter = OllamaAdapter;
        let request = serde_json::json!({
            "model": "llama3",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ]
        });

        let result = adapter.translate_request(&request);

        assert_eq!(result["model"], "llama3");
        assert!(result.get("messages").is_some());
        assert_eq!(result["max_tokens"], 4096);
    }

    #[test]
    fn test_ollama_base_url() {
        let adapter = OllamaAdapter;
        assert_eq!(adapter.base_url(), "http://localhost:11434/v1");
    }

    #[test]
    fn test_ollama_required_headers() {
        let adapter = OllamaAdapter;
        let headers = adapter.required_headers("test-key");

        assert_eq!(headers.get("Authorization").unwrap(), "Bearer test-key");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn test_ollama_required_headers_empty_key() {
        let adapter = OllamaAdapter;
        let headers = adapter.required_headers("");

        assert!(headers.get("Authorization").is_none());
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn test_azure_openai_adapter() {
        let adapter = AzureOpenAIAdapter::new(
            "my-resource".to_string(),
            "gpt-4".to_string(),
            "2024-02-01".to_string(),
        );

        let request = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ]
        });

        let result = adapter.translate_request(&request);

        assert_eq!(result["model"], "gpt-4");
        assert!(result.get("messages").is_some());
        assert_eq!(result["max_tokens"], 4096);
    }

    #[test]
    fn test_azure_openai_response_passthrough() {
        let adapter = AzureOpenAIAdapter::new(
            "my-resource".to_string(),
            "gpt-4".to_string(),
            "2024-02-01".to_string(),
        );

        let response = serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "Hi!"}}]
        });

        let result = adapter.translate_response(&response);
        assert_eq!(result, response);
    }

    #[test]
    fn test_azure_openai_base_url() {
        let adapter = AzureOpenAIAdapter::new(
            "my-resource".to_string(),
            "gpt-4".to_string(),
            "2024-02-01".to_string(),
        );

        assert_eq!(adapter.base_url(), "https://PLACEHOLDER.openai.azure.com");
    }

    #[test]
    fn test_azure_openai_endpoint_path() {
        let adapter = AzureOpenAIAdapter::new(
            "my-resource".to_string(),
            "gpt-4".to_string(),
            "2024-02-01".to_string(),
        );

        assert_eq!(
            adapter.endpoint_path(),
            "openai/deployments/{deployment_id}/chat/completions"
        );
    }

    #[test]
    fn test_azure_openai_required_headers() {
        let adapter = AzureOpenAIAdapter::new(
            "my-resource".to_string(),
            "gpt-4".to_string(),
            "2024-02-01".to_string(),
        );

        let headers = adapter.required_headers("test-key");

        assert_eq!(headers.get("api-key").unwrap(), "test-key");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
        assert_eq!(headers.get("api-version").unwrap(), "2024-02-01");
    }

    #[test]
    fn test_bedrock_adapter() {
        let adapter = AWSBedrockAdapter::new(
            "us-east-1".to_string(),
            "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
        );

        let request = serde_json::json!({
            "model": "anthropic.claude-3-sonnet-20240229-v1:0",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello!"}
            ],
            "max_tokens": 100,
            "temperature": 0.7
        });

        let result = adapter.translate_request(&request);

        assert!(result.get("messages").is_some());
        assert_eq!(result["max_tokens"], 100);
        assert_eq!(result["temperature"], 0.7);
        assert_eq!(result["system"], "You are a helpful assistant.");
    }

    #[test]
    fn test_bedrock_response_translation() {
        let adapter = AWSBedrockAdapter::new(
            "us-east-1".to_string(),
            "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
        );

        let response = serde_json::json!({
            "content": [
                {"type": "text", "text": "Hello! How can I help?"}
            ],
            "stop_reason": "end_turn"
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
    fn test_bedrock_base_url() {
        let adapter = AWSBedrockAdapter::new(
            "us-east-1".to_string(),
            "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
        );

        assert_eq!(
            adapter.base_url(),
            "https://bedrock-runtime.{region}.amazonaws.com"
        );
    }

    #[test]
    fn test_bedrock_endpoint_path() {
        let adapter = AWSBedrockAdapter::new(
            "us-east-1".to_string(),
            "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
        );

        assert_eq!(adapter.endpoint_path(), "model/{model_id}/invoke");
    }

    #[test]
    fn test_bedrock_required_headers() {
        let adapter = AWSBedrockAdapter::new(
            "us-east-1".to_string(),
            "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
        );

        let headers = adapter.required_headers("test-key");

        assert_eq!(headers.get("Authorization").unwrap(), "Bearer test-key");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
        assert_eq!(
            headers.get("X-Amz-Target").unwrap(),
            "BedrockRuntime.InvokeModel"
        );
    }
}
