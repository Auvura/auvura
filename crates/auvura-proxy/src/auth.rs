//! Authentication middleware for the proxy

use axum::{
    extract::Request,
    http::header::AUTHORIZATION,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// Shared authentication state containing valid API keys.
#[derive(Clone)]
pub struct AuthState {
    keys: Arc<Vec<String>>,
}

impl AuthState {
    /// Create a new AuthState from resolved API keys.
    pub fn new(keys: Vec<String>) -> Self {
        Self {
            keys: Arc::new(keys),
        }
    }

    /// Check if a given token is valid.
    pub fn is_valid(&self, token: &str) -> bool {
        self.keys.iter().any(|k| k == token)
    }
}

/// Authentication middleware layer.
/// Extracts Bearer token from Authorization header and validates against configured keys.
/// Skips authentication for health check endpoint.
pub async fn auth_middleware(request: Request, next: Next) -> Response {
    // Skip authentication for health check endpoint
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }

    // Extract auth state from extensions
    let auth_state = request
        .extensions()
        .get::<AuthState>()
        .cloned()
        .expect("AuthState must be added to request extensions");

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) => {
            // Parse Bearer token
            if let Some(token) = header.strip_prefix("Bearer ") {
                if auth_state.is_valid(token) {
                    return next.run(request).await;
                }
            }
            // Invalid or missing token
            unauthorized_response()
        }
        None => unauthorized_response(),
    }
}

/// Build a 401 Unauthorized response.
fn unauthorized_response() -> Response {
    let body = serde_json::json!({
        "error": "Unauthorized",
        "message": "Missing or invalid API key. Provide a valid API key in the Authorization header: Bearer <api-key>"
    });

    (
        StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
        axum::Json(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_state_is_valid() {
        let state = AuthState::new(vec!["key1".to_string(), "key2".to_string()]);

        assert!(state.is_valid("key1"));
        assert!(state.is_valid("key2"));
        assert!(!state.is_valid("key3"));
        assert!(!state.is_valid(""));
    }

    #[test]
    fn test_auth_state_empty_keys() {
        let state = AuthState::new(vec![]);
        assert!(!state.is_valid("anything"));
    }
}
