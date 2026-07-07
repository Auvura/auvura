//! Metrics collection and Prometheus exporter for Auvura Proxy.
//!
//! Provides request count, latency histograms, and PII detection rates.

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use metrics::{counter, describe_counter, describe_histogram, histogram, Unit};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Metrics state holding the Prometheus handle.
#[derive(Clone)]
pub struct MetricsState {
    pub handle: PrometheusHandle,
}

impl Default for MetricsState {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsState {
    /// Initialize the Prometheus exporter and register metrics.
    pub fn new() -> Self {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("Failed to install Prometheus recorder");

        // Describe metrics
        describe_counter!(
            "auvura_requests_total",
            Unit::Count,
            "Total number of HTTP requests"
        );
        describe_counter!(
            "auvura_requests_by_status",
            Unit::Count,
            "Requests grouped by status code"
        );
        describe_counter!(
            "auvura_requests_by_endpoint",
            Unit::Count,
            "Requests grouped by endpoint"
        );
        describe_counter!(
            "auvura_pii_detections_total",
            Unit::Count,
            "Total PII detections"
        );
        describe_counter!(
            "auvura_pii_by_type",
            Unit::Count,
            "PII detections grouped by type"
        );
        describe_histogram!(
            "auvura_request_duration_seconds",
            Unit::Seconds,
            "Request duration in seconds"
        );
        describe_histogram!(
            "auvura_redaction_duration_seconds",
            Unit::Seconds,
            "Redaction processing duration in seconds"
        );
        describe_counter!(
            "auvura_provider_requests_total",
            Unit::Count,
            "Total upstream provider requests"
        );
        describe_counter!(
            "auvura_provider_errors_total",
            Unit::Count,
            "Upstream provider errors"
        );

        info!("Prometheus metrics exporter initialized");

        Self { handle }
    }

    /// Record a request with status and duration.
    pub fn record_request(method: &str, path: &str, status: u16, duration_secs: f64) {
        counter!("auvura_requests_total", "method" => method.to_string(), "path" => path.to_string()).increment(1);
        counter!("auvura_requests_by_status", "status" => status.to_string()).increment(1);
        counter!("auvura_requests_by_endpoint", "endpoint" => path.to_string()).increment(1);
        histogram!("auvura_request_duration_seconds", "method" => method.to_string(), "path" => path.to_string()).record(duration_secs);
    }

    /// Record a PII detection event.
    pub fn record_pii_detection(pii_type: &str) {
        counter!("auvura_pii_detections_total").increment(1);
        counter!("auvura_pii_by_type", "type" => pii_type.to_string()).increment(1);
    }

    /// Record redaction processing duration.
    pub fn record_redaction_duration(duration_secs: f64) {
        histogram!("auvura_redaction_duration_seconds").record(duration_secs);
    }

    /// Record an upstream provider request.
    pub fn record_provider_request(provider: &str) {
        counter!("auvura_provider_requests_total", "provider" => provider.to_string()).increment(1);
    }

    /// Record an upstream provider error.
    pub fn record_provider_error(provider: &str, error_type: &str) {
        counter!("auvura_provider_errors_total", "provider" => provider.to_string(), "error" => error_type.to_string()).increment(1);
    }
}

/// Handler for `/metrics` endpoint.
async fn metrics_handler(State(state): State<Arc<MetricsState>>) -> impl IntoResponse {
    let metrics = state.handle.render();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics,
    )
        .into_response()
}

/// Build the metrics router with the `/metrics` endpoint.
pub fn metrics_router(state: Arc<MetricsState>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// Timer helper for measuring durations.
pub struct RequestTimer {
    start: Instant,
}

impl RequestTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}
