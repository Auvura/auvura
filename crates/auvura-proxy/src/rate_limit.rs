//! Simple per-IP token bucket rate limiter using DashMap.
//!
//! Each IP gets a bucket with `max_tokens` capacity that refills at
//! `refill_rate` tokens per second. When a bucket is empty, requests
//! are rejected with 429 Too Many Requests.

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::response::Response;
use dashmap::DashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tower::{Layer, Service};

/// Per-IP rate limiter state.
#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl Bucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            last_refill: Instant::now(),
            max_tokens,
            refill_rate,
        }
    }

    /// Try to consume one token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared rate limiter state keyed by IP hash.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<DashMap<u64, Bucket>>,
    max_tokens: f64,
    refill_rate: f64,
}

impl RateLimiter {
    pub fn new(requests_per_second: u64, burst_size: u64) -> Self {
        let max_tokens = burst_size as f64;
        let refill_rate = requests_per_second as f64;
        Self {
            buckets: Arc::new(DashMap::new()),
            max_tokens,
            refill_rate,
        }
    }

    fn key_for(addr: SocketAddr) -> u64 {
        let mut hasher = DefaultHasher::new();
        addr.ip().hash(&mut hasher);
        hasher.finish()
    }

    /// Check if a request from the given address is allowed.
    pub fn is_allowed(&self, addr: SocketAddr) -> bool {
        let key = Self::key_for(addr);
        if let Some(mut bucket) = self.buckets.get_mut(&key) {
            return bucket.try_consume();
        }
        // Insert new bucket and try
        self.buckets
            .insert(key, Bucket::new(self.max_tokens, self.refill_rate));
        self.buckets.get_mut(&key).unwrap().try_consume()
    }
}

/// Tower layer that applies per-IP rate limiting.
#[derive(Clone)]
pub struct RateLimitLayer {
    pub limiter: RateLimiter,
}

impl RateLimitLayer {
    pub fn new(requests_per_second: u64, burst_size: u64) -> Self {
        Self {
            limiter: RateLimiter::new(requests_per_second, burst_size),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

/// Tower service that enforces per-IP rate limiting.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    limiter: RateLimiter,
}

impl<S> Service<axum::http::Request<axum::body::Body>> for RateLimitService<S>
where
    S: Service<axum::http::Request<axum::body::Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<axum::body::Body>) -> Self::Future {
        // Extract client IP from X-Forwarded-For, X-Real-IP, or socket addr
        let client_ip = extract_client_ip(&req);

        if !self.limiter.is_allowed(client_ip) {
            let response = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("content-type", "application/json")
                .header("retry-after", "1")
                .body(axum::body::Body::from(
                    r#"{"error":"rate limit exceeded, try again later"}"#,
                ))
                .unwrap();
            return Box::pin(async { Ok(response) });
        }

        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

/// Extract client IP from request headers or socket address.
fn extract_client_ip<B>(req: &axum::http::Request<B>) -> SocketAddr {
    // Try X-Forwarded-For first (first IP is the client)
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = forwarded.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(addr) = first.trim().parse::<SocketAddr>() {
                    return addr;
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(s) = real_ip.to_str() {
            if let Ok(addr) = s.parse::<SocketAddr>() {
                return addr;
            }
        }
    }

    // Fall back to ConnectInfo or a dummy address
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_allows_within_burst() {
        let mut bucket = Bucket::new(5.0, 10.0);
        for _ in 0..5 {
            assert!(bucket.try_consume());
        }
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_rate_limiter_allows_normal_traffic() {
        let limiter = RateLimiter::new(10, 10);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        // Should allow burst
        for _ in 0..10 {
            assert!(limiter.is_allowed(addr));
        }
    }

    #[test]
    fn test_rate_limiter_rejects_over_limit() {
        let limiter = RateLimiter::new(2, 2);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(limiter.is_allowed(addr));
        assert!(limiter.is_allowed(addr));
        assert!(!limiter.is_allowed(addr));
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = RateLimiter::new(1, 1);
        let addr1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.2:8080".parse().unwrap();
        assert!(limiter.is_allowed(addr1));
        assert!(!limiter.is_allowed(addr1)); // exhausted
        assert!(limiter.is_allowed(addr2)); // different IP, still has tokens
    }
}
