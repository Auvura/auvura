use auvura_core::detector::PiiDetector;
use auvura_core::detectors::credit_card::CreditCardDetector;
use auvura_core::detectors::email::EmailDetector;
use auvura_core::detectors::ip::{Ipv4Detector, Ipv6Detector};
use auvura_core::detectors::phone_number::PhoneNumberDetector;
use auvura_core::detectors::ssn::SSNDetector;
use auvura_core::json::JsonRedactor;
use auvura_core::policy::RedactionPolicy;
use auvura_core::redactor::Redactor;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn build_redactor() -> Redactor {
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

fn bench_redact_no_pii(c: &mut Criterion) {
    let redactor = build_redactor();
    let text = "This is a normal sentence with no personally identifiable information whatsoever.";
    c.bench_function("redact_no_pii", |b| {
        b.iter(|| redactor.redact(black_box(text)))
    });
}

fn bench_redact_email(c: &mut Criterion) {
    let redactor = build_redactor();
    let text = "Contact john.doe@example.com for more information about our services.";
    c.bench_function("redact_email", |b| {
        b.iter(|| redactor.redact(black_box(text)))
    });
}

fn bench_redact_multiple_pii(c: &mut Criterion) {
    let redactor = build_redactor();
    let text = "Email john@example.com, SSN 123-45-6789, Card 4111 1111 1111 1111, IP 192.168.1.1";
    c.bench_function("redact_multiple_pii", |b| {
        b.iter(|| redactor.redact(black_box(text)))
    });
}

fn bench_redact_long_text(c: &mut Criterion) {
    let redactor = build_redactor();
    let mut text = String::new();
    for i in 0..1000 {
        text.push_str(&format!(
            "Sentence {} with email user{}@example.com. ",
            i, i
        ));
    }
    c.bench_function("redact_long_text_1k_emails", |b| {
        b.iter(|| redactor.redact(black_box(&text)))
    });
}

fn bench_json_redact_simple(c: &mut Criterion) {
    let jr = JsonRedactor::new(build_redactor());
    let json = r#"{"name": "Alice", "email": "alice@example.com", "age": 30}"#;
    c.bench_function("json_redact_simple", |b| {
        b.iter(|| jr.redact_json(black_box(json)).unwrap())
    });
}

fn bench_json_redact_nested(c: &mut Criterion) {
    let jr = JsonRedactor::new(build_redactor());
    let json = r#"{"users": [{"email": "a@b.com", "ssn": "123-45-6789"}, {"email": "c@d.com", "card": "4111 1111 1111 1111"}], "admin": {"email": "admin@example.com"}}"#;
    c.bench_function("json_redact_nested", |b| {
        b.iter(|| jr.redact_json(black_box(json)).unwrap())
    });
}

fn bench_json_redact_no_pii(c: &mut Criterion) {
    let jr = JsonRedactor::new(build_redactor());
    let json = r#"{"name": "Alice", "age": 30, "city": "Seattle", "active": true}"#;
    c.bench_function("json_redact_no_pii", |b| {
        b.iter(|| jr.redact_json(black_box(json)).unwrap())
    });
}

fn bench_detection_only(c: &mut Criterion) {
    let email_detector = EmailDetector::new();
    let text = "Send to john@example.com and jane@example.com";
    c.bench_function("detect_emails_only", |b| {
        b.iter(|| email_detector.detect(black_box(text)))
    });
}

criterion_group!(
    benches,
    bench_redact_no_pii,
    bench_redact_email,
    bench_redact_multiple_pii,
    bench_redact_long_text,
    bench_json_redact_simple,
    bench_json_redact_nested,
    bench_json_redact_no_pii,
    bench_detection_only,
);
criterion_main!(benches);
