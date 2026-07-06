//! Structured audit logging for GDPR/HIPAA compliance.
//!
//! Records detection and redaction events with timestamps, PII types,
//! and redacted forms for compliance audit trails.
//!
//! # Example
//!
//! ```rust
//! use auvura_core::audit::{AuditLogger, JsonAuditLogger, AuditEvent};
//!
//! let logger = JsonAuditLogger::new();
//! logger.log(AuditEvent::Detection {
//!     pii_type: "email".to_string(),
//!     confidence: "medium".to_string(),
//!     start: 15,
//!     end: 35,
//!     original_len: 20,
//!     redacted_form: "████.███@███████.com".to_string(),
//! });
//!
//! let events = logger.events();
//! assert_eq!(events.len(), 1);
//! ```

use crate::detector::Detection;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// A single audit event recording a detection or redaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// PII was detected in input text.
    Detection {
        /// PII type detected (e.g., "email", "ssn").
        pii_type: String,
        /// Confidence level (e.g., "high", "medium", "low").
        confidence: String,
        /// Byte offset start in original text.
        start: usize,
        /// Byte offset end in original text.
        end: usize,
        /// Length of original matched text (bytes).
        original_len: usize,
        /// The redacted form that replaced this detection.
        redacted_form: String,
    },
    /// A request was processed through the redactor.
    RequestProcessed {
        /// Whether any PII was found and redacted.
        had_pii: bool,
        /// Number of PII detections in this request.
        detection_count: usize,
        /// Whether the output differs from input (redaction occurred).
        redacted: bool,
    },
    /// An explicit audit log message with free-form detail.
    Custom {
        /// Event category (e.g., "auth", "config", "error").
        category: String,
        /// Human-readable message.
        message: String,
    },
}

impl AuditEvent {
    /// Create a Detection event from a `Detection` and its redacted form.
    pub fn from_detection(detection: &Detection, redacted_form: &str) -> Self {
        AuditEvent::Detection {
            pii_type: format!("{:?}", detection.pii_type).to_lowercase(),
            confidence: format!("{:?}", detection.confidence).to_lowercase(),
            start: detection.start,
            end: detection.end,
            original_len: detection.original.len(),
            redacted_form: redacted_form.to_string(),
        }
    }

    /// Timestamp this event (returns an `AuditedEvent` with ISO-8601 timestamp).
    pub fn with_timestamp(self) -> AuditedEvent {
        AuditedEvent {
            timestamp: chrono_timestamp(),
            event: self,
        }
    }
}

/// An audit event with an ISO-8601 timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditedEvent {
    /// ISO-8601 timestamp (e.g., "2024-01-15T10:30:00Z").
    pub timestamp: String,
    /// The audit event.
    #[serde(flatten)]
    pub event: AuditEvent,
}

/// Trait for audit loggers.
///
/// Implement this trait to send audit events to your logging infrastructure
/// (e.g., file, syslog, cloud logging, database).
pub trait AuditLogger: Send + Sync {
    /// Log an audit event.
    fn log(&self, event: AuditEvent);

    /// Flush any buffered events (optional, for batch writers).
    fn flush(&self) {}

    /// Return all logged events (for testing and in-memory loggers).
    fn events(&self) -> Vec<AuditedEvent>;
}

/// In-memory JSON audit logger.
///
/// Stores all events in a thread-safe `Vec`. Useful for testing and
/// development. For production, implement `AuditLogger` to write to
/// your logging infrastructure.
///
/// # Example
///
/// ```rust
/// use auvura_core::audit::{JsonAuditLogger, AuditEvent, AuditLogger};
///
/// let logger = JsonAuditLogger::new();
/// logger.log(AuditEvent::Custom {
///     category: "config".to_string(),
///     message: "Server started on port 3000".to_string(),
/// });
///
/// // Retrieve logged events
/// let events = logger.events();
/// assert_eq!(events.len(), 1);
/// ```
pub struct JsonAuditLogger {
    events: Arc<Mutex<Vec<AuditedEvent>>>,
}

impl JsonAuditLogger {
    /// Create a new empty JSON audit logger.
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a new logger pre-allocated with capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
        }
    }

    /// Clear all stored events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    /// Return the number of stored events.
    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Return true if no events are stored.
    pub fn is_empty(&self) -> bool {
        self.events.lock().unwrap().is_empty()
    }

    /// Serialize all events to JSON.
    pub fn to_json(&self) -> String {
        let events = self.events.lock().unwrap();
        serde_json::to_string_pretty(&*events).unwrap_or_else(|_| "[]".to_string())
    }
}

impl Default for JsonAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger for JsonAuditLogger {
    fn log(&self, event: AuditEvent) {
        let audited = event.with_timestamp();
        self.events.lock().unwrap().push(audited);
    }

    fn events(&self) -> Vec<AuditedEvent> {
        self.events.lock().unwrap().clone()
    }
}

/// No-op audit logger that discards all events.
///
/// Use when audit logging is disabled.
pub struct NoopAuditLogger;

impl AuditLogger for NoopAuditLogger {
    fn log(&self, _event: AuditEvent) {}

    fn events(&self) -> Vec<AuditedEvent> {
        Vec::new()
    }
}

/// Get current timestamp in ISO-8601 format.
///
/// Uses a simple implementation without external datetime crate dependency.
/// Format: "2024-01-15T10:30:00Z" (UTC).
fn chrono_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert to broken-down time (simplified UTC)
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Days since epoch to Y-M-D (simplified, not accounting for leap years precisely)
    let mut year = 1970;
    let mut day_of_year = days;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if day_of_year < days_in_year {
            break;
        }
        day_of_year -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &md in &month_days {
        if day_of_year < md as u64 {
            break;
        }
        day_of_year -= md as u64;
        month += 1;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day_of_year + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PiiType;

    #[test]
    fn test_audit_event_detection() {
        let detection = Detection {
            pii_type: PiiType::Email,
            confidence: crate::detector::Confidence::Medium,
            start: 15,
            end: 35,
            original: "john@example.com".to_string(),
        };
        let event = AuditEvent::from_detection(&detection, "████.███@███████.com");
        match event {
            AuditEvent::Detection {
                pii_type,
                confidence,
                start,
                end,
                original_len,
                redacted_form,
            } => {
                assert_eq!(pii_type, "email");
                assert_eq!(confidence, "medium");
                assert_eq!(start, 15);
                assert_eq!(end, 35);
                assert_eq!(original_len, 16);
                assert_eq!(redacted_form, "████.███@███████.com");
            }
            _ => panic!("Expected Detection event"),
        }
    }

    #[test]
    fn test_json_logger_stores_events() {
        let logger = JsonAuditLogger::new();
        assert!(logger.is_empty());

        logger.log(AuditEvent::Custom {
            category: "test".to_string(),
            message: "hello".to_string(),
        });

        assert_eq!(logger.len(), 1);
        let events = logger.events();
        assert_eq!(events[0].event, AuditEvent::Custom {
            category: "test".to_string(),
            message: "hello".to_string(),
        });
        assert!(!events[0].timestamp.is_empty());
    }

    #[test]
    fn test_json_logger_clear() {
        let logger = JsonAuditLogger::new();
        logger.log(AuditEvent::Custom {
            category: "test".to_string(),
            message: "hello".to_string(),
        });
        assert_eq!(logger.len(), 1);

        logger.clear();
        assert!(logger.is_empty());
    }

    #[test]
    fn test_json_logger_serialization() {
        let logger = JsonAuditLogger::new();
        logger.log(AuditEvent::Custom {
            category: "test".to_string(),
            message: "hello".to_string(),
        });

        let json = logger.to_json();
        assert!(json.contains("test"));
        assert!(json.contains("hello"));
        assert!(json.contains("timestamp"));
    }

    #[test]
    fn test_noop_logger_discards() {
        let logger = NoopAuditLogger;
        logger.log(AuditEvent::Custom {
            category: "test".to_string(),
            message: "hello".to_string(),
        });
        assert!(logger.events().is_empty());
    }

    #[test]
    fn test_request_processed_event() {
        let event = AuditEvent::RequestProcessed {
            had_pii: true,
            detection_count: 3,
            redacted: true,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("request_processed"));
        assert!(json.contains("\"had_pii\":true"));
        assert!(json.contains("\"detection_count\":3"));
    }

    #[test]
    fn test_timestamp_format() {
        let ts = chrono_timestamp();
        // Should be ISO-8601-like: "YYYY-MM-DDTHH:MM:SSZ"
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        assert!(ts.contains('-'));
        assert!(ts.contains(':'));
    }

    #[test]
    fn test_detection_event_serialization_roundtrip() {
        let event = AuditEvent::Detection {
            pii_type: "ssn".to_string(),
            confidence: "high".to_string(),
            start: 0,
            end: 11,
            original_len: 11,
            redacted_form: "███-██-████".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn test_audited_event_serialization() {
        let audited = AuditEvent::Custom {
            category: "auth".to_string(),
            message: "login successful".to_string(),
        }
        .with_timestamp();

        let json = serde_json::to_string(&audited).unwrap();
        assert!(json.contains("timestamp"));
        assert!(json.contains("auth"));

        let parsed: AuditedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event, audited.event);
    }
}
