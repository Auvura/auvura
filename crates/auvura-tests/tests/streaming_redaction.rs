//! Integration tests for streaming redaction API.
//!
//! Tests the full flow: stream creation → chunked redaction → output verification.

use auvura_core::detector::PiiDetector;
use auvura_core::detectors::credit_card::CreditCardDetector;
use auvura_core::detectors::email::EmailDetector;
use auvura_core::detectors::ip::{Ipv4Detector, Ipv6Detector};
use auvura_core::detectors::phone_number::PhoneNumberDetector;
use auvura_core::detectors::ssn::SSNDetector;
use auvura_core::policy::RedactionPolicy;
use auvura_core::redactor::Redactor;
use auvura_core::stream::{RedactorStreamExt, StreamingRedactor};
use futures::stream;
use futures::{Stream, StreamExt};

fn full_redactor() -> Redactor {
    let detectors: Vec<Box<dyn PiiDetector>> = vec![
        Box::new(EmailDetector::new()),
        Box::new(PhoneNumberDetector::new()),
        Box::new(SSNDetector::new()),
        Box::new(CreditCardDetector::new()),
        Box::new(Ipv4Detector::new()),
        Box::new(Ipv6Detector::new()),
    ];
    Redactor::new(detectors, RedactionPolicy::default())
}

#[tokio::test]
async fn stream_no_pii_passthrough() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks = vec![
        Ok::<_, std::io::Error>("hello ".to_string()),
        Ok("world".to_string()),
    ];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].as_ref().unwrap(), "hello ");
    assert_eq!(results[1].as_ref().unwrap(), "world");
}

#[tokio::test]
async fn stream_redacts_email() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks = vec![
        Ok::<_, std::io::Error>("Email: ".to_string()),
        Ok("test@example.com ".to_string()),
        Ok("for info".to_string()),
    ];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    let output: String = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    assert!(output.contains("@"));
    assert!(!output.contains("test@example.com"));
}

#[tokio::test]
async fn stream_redacts_ssn() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks = vec![
        Ok::<_, std::io::Error>("SSN: 123-".to_string()),
        Ok("45-6789".to_string()),
    ];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    let output: String = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    assert!(output.contains("SSN:"));
    assert!(!output.contains("123-45-6789"));
}

#[tokio::test]
async fn stream_redacts_credit_card() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks = vec![
        Ok::<_, std::io::Error>("Card: 4111 ".to_string()),
        Ok("1111 1111 1111".to_string()),
    ];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    let output: String = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    assert!(output.contains("Card:"));
    assert!(!output.contains("4111 1111 1111 1111"));
}

#[tokio::test]
async fn stream_error_propagation() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks = vec![
        Ok::<_, std::io::Error>("hello ".to_string()),
        Err(std::io::Error::other("test error")),
    ];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
}

#[tokio::test]
async fn stream_empty_input() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks: Vec<Result<String, std::io::Error>> = vec![];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    assert!(results.is_empty());
}

#[tokio::test]
async fn stream_many_small_chunks() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks: Vec<Result<String, std::io::Error>> = "Contact john@example.com now"
        .chars()
        .map(|c| Ok(c.to_string()))
        .collect();
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    let output: String = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    assert!(output.contains("Contact"));
    assert!(output.contains("now"));
    assert!(!output.contains("john@example.com"));
}

#[tokio::test]
async fn stream_newline_delimited() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks = vec![
        Ok::<_, std::io::Error>("line1\n".to_string()),
        Ok("line2 with test@example.com\n".to_string()),
        Ok("line3\n".to_string()),
    ];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    let output: String = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    assert!(output.contains("line1"));
    assert!(output.contains("line3"));
    assert!(!output.contains("test@example.com"));
}

#[tokio::test]
async fn stream_extension_trait() {
    let redactor = full_redactor();
    let chunks = vec![
        Ok::<_, std::io::Error>("Email: ".to_string()),
        Ok("user@host.com".to_string()),
    ];
    let results: Vec<_> = redactor.redact_stream(stream::iter(chunks)).collect().await;
    let output: String = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    assert!(!output.contains("user@host.com"));
}

#[tokio::test]
async fn stream_single_large_chunk() {
    let sr = StreamingRedactor::new(full_redactor());
    // Credit card with trailing whitespace so it gets flushed at boundary
    let input = "Email: test@example.com, SSN: 123-45-6789, Card: 4111 1111 1111 1111 ";
    let chunks = vec![Ok::<_, std::io::Error>(input.to_string())];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    let output: String = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    assert!(!output.contains("test@example.com"));
    assert!(!output.contains("123-45-6789"));
    assert!(!output.contains("4111 1111 1111 1111"));
}

#[tokio::test]
async fn stream_phone_number() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks = vec![
        Ok::<_, std::io::Error>("Call ".to_string()),
        Ok("+12025550123".to_string()),
        Ok(" now".to_string()),
    ];
    let results: Vec<_> = sr.redact_stream(stream::iter(chunks)).collect().await;
    let output: String = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    assert!(output.contains("Call"));
    assert!(!output.contains("+12025550123"));
}

#[tokio::test]
async fn stream_size_hint() {
    let sr = StreamingRedactor::new(full_redactor());
    let chunks = vec![
        Ok::<_, std::io::Error>("a".to_string()),
        Ok("b".to_string()),
        Ok("c".to_string()),
    ];
    let redacted = sr.redact_stream(stream::iter(chunks));
    let (lo, hi) = redacted.size_hint();
    assert_eq!(lo, 3);
    assert_eq!(hi, Some(4)); // 3 + 1 extra from buffer flush
}
