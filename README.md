# Auvura

**High-performance, local-first PII-Shield for LLMs. Built in Rust.**

Auvura is a Rust workspace that provides **PII (Personally Identifiable Information) detection and redaction** for AI applications. It acts as a security layer that ensures sensitive data never leaves your local environment when interacting with cloud AI providers.

## Features

- **PII Detection**: Email, Phone Number, SSN, Credit Card, IP Address, IBAN, Passport, National ID, Physical Address
- **Confidence Scoring**: Each detection includes a confidence level (High/Medium/Low) based on detection method
- **Compliance-Ready**: GDPR, HIPAA, PCI-DSS profiles included
- **Structured Redaction**: Preserves format while masking sensitive data
- **JSON-Aware Redaction**: Redacts PII inside JSON string values while preserving structure
- **Streaming Redaction**: Real-time PII redaction for async text streams
- **Memory Safe**: Uses `zeroize` crate to securely erase detections from memory
- **Provider-Agnostic Proxy**: OpenAI-compatible endpoint that forwards to any AI provider (OpenAI, Anthropic, Gemini, Mistral, Cohere, Azure, Bedrock, Ollama)
- **High Performance**: Built in Rust with zero-copy optimizations

## Project Structure

```
auvura/
├── crates/
│   ├── auvura-core/          # Core PII detection library
│   │   ├── src/
│   │   │   ├── types.rs        # PII type definitions with regulatory basis
│   │   │   ├── detector.rs     # Detector trait + MultiDetector
│   │   │   ├── policy.rs       # Redaction policies + compliance profiles
│   │   │   ├── redactor.rs     # Core redaction engine
│   │   │   ├── audit.rs        # Structured audit logging (GDPR/HIPAA)
│   │   │   ├── json.rs         # JSON-structure-aware redaction
│   │   │   ├── stream.rs       # Streaming redaction for async pipelines
│   │   │   └── detectors/      # Individual detectors
│   │   │       ├── email.rs
│   │   │       ├── phone_number.rs
│   │   │       ├── ssn.rs
│   │   │       ├── credit_card.rs
│   │   │       ├── ip.rs
│   │   │       ├── iban.rs
│   │   │       ├── passport.rs
│   │   │       ├── national_id.rs
│   │   │       ├── address.rs
│   │   │       └── ner.rs
│   │   └── benches/          # Criterion benchmarks
│   ├── auvura-cli/          # CLI binary (redact, validate, serve)
│   ├── auvura-proxy/        # Proxy server for AI API redaction
│   │   └── src/
│   │       ├── main.rs        # Axum server with /v1/chat/completions
│   │       ├── config.rs      # TOML config + CLI arg parsing
│   │       ├── provider.rs    # Provider-agnostic adapter system
│   │       └── rate_limit.rs  # Per-IP token bucket rate limiter
│   └── auvura-tests/        # Integration tests
│       └── tests/
│           ├── redaction_pipeline.rs
│           ├── json_redaction.rs
│           ├── streaming_redaction.rs
│           ├── policy_roundtrip.rs
│           └── edge_cases.rs
├── fuzz/                     # Fuzz testing targets
│   └── fuzz_targets/
│       ├── fuzz_redactor.rs
│       ├── fuzz_json_redactor.rs
│       └── fuzz_detectors.rs
└── Cargo.toml                # Workspace configuration
```

## Quick Start

### Core Library

```rust
use auvura_core::{detector::*, policy::*, redactor::Redactor};

// Create detectors
let detectors: Vec<Box<dyn PiiDetector>> = vec![
    Box::new(detectors::EmailDetector::new()),
    Box::new(detectors::PhoneNumberDetector::new()),
    Box::new(detectors::SSNDetector::new()),
    Box::new(detectors::CreditCardDetector::new()),
];

// Create policy (use defaults or compliance profiles)
let policy = RedactionPolicy::default();  // All types enabled
// let policy = RedactionPolicy::gdpr();  // GDPR profile
// let policy = RedactionPolicy::hipaa();  // HIPAA profile
// let policy = RedactionPolicy::pci_dss();  // PCI-DSS profile

// Create redactor
let redactor = Redactor::new(detectors, policy);

// Redact PII
let input = "Contact john@example.com or call 123-456-7890";
let result = redactor.redact(input);
println!("{}", result);
// Output: "Contact ████.███@███████.com or call ███-███-████"

// Custom placeholders (override format-preserving redaction)
let policy = RedactionPolicy::builder()
    .with_placeholder(PiiType::Email, "[EMAIL]")
    .with_placeholder(PiiType::PhoneNumber, "[PHONE]")
    .build();
let redactor = Redactor::new(detectors, policy);
let result = redactor.redact("Email john@example.com or call 123-456-7890");
println!("{}", result);
// Output: "Email [EMAIL] or call [PHONE]"

// Custom phone country list (ISO 3166-1 alpha-2 codes)
// Default: ["US", "GB", "DE", "FR", "CA", "AU", "JP"]
let detector = detectors::PhoneNumberDetector::with_countries(
    vec!["DE".into(), "FR".into(), "JP".into()]
);
```

#### Policy Serialization

`RedactionPolicy` supports serialization to/from JSON, TOML, or any serde-compatible format via `RedactionPolicyConfig`:

```rust
use auvura_core::policy::{RedactionPolicy, RedactionPolicyConfig};

// Create a policy
let policy = RedactionPolicy::builder()
    .disable(PiiType::Ssn)
    .with_blocklist(vec!["SECRET"])
    .with_allowlist(vec!["Apple"])
    .build();

// Serialize to config
let config = policy.serialize();

// Convert to JSON
let json = serde_json::to_string_pretty(&config).unwrap();
println!("{}", json);
// {
//   "enabled_types": ["email", "phone_number", "credit_card", "ip_address_v4", "ip_address_v6"],
//   "placeholders": {},
//   "allowlist": ["Apple"],
//   "blocklist": ["SECRET"],
//   "strict_validation": true
// }

// Deserialize from JSON/TOML
let config: RedactionPolicyConfig = serde_json::from_str(&json).unwrap();
let restored = RedactionPolicy::from_config(&config);
```

#### Confidence Scoring

Each detection includes a confidence level indicating how certain we are that the detected text is PII:

```rust
use auvura_core::detector::Confidence;

// Confidence levels:
// - High: regex + checksum/validation (SSN, CreditCard with Luhn, IBAN with mod-97, IP addresses)
// - Medium: regex pattern only (Email, PhoneNumber, Passport, NationalId)
// - Low: heuristic/pattern matching (PhysicalAddress)

let detector = detectors::EmailDetector::new();
assert_eq!(detector.confidence(), Confidence::Medium);

let detector = detectors::SSNDetector::new();
assert_eq!(detector.confidence(), Confidence::High);

// Access confidence from detection
let detections = detector.detect("SSN: 123-45-6789");
assert_eq!(detections[0].confidence, Confidence::High);
```

Confidence is used as a tiebreaker when resolving overlapping detections:
- Higher priority PII type wins first
- If same priority, higher confidence wins
- If same confidence, longer span wins

#### JSON-Aware Redaction

Redact PII inside JSON string values while preserving structure (keys, numbers, arrays):

```rust
use auvura_core::json::JsonRedactor;
use auvura_core::redactor::Redactor;

let redactor = Redactor::new(detectors, policy);
let json_redactor = JsonRedactor::new(redactor);

let input = r#"{"email": "john@example.com", "ssn": "123-45-6789", "age": 30}"#;
let result = json_redactor.redact_json(input).unwrap();
// {"email":"████.███@███████.com","ssn":"███-██-████","age":30}
```

#### Streaming Redaction

Real-time PII redaction for async text streams (e.g., SSE from LLMs):

```rust
use auvura_core::stream::StreamingRedactor;
use futures::stream;

let streaming = StreamingRedactor::new(redactor);
let chunks = stream::iter(vec![
    Ok::<_, std::io::Error>("Contact ".to_string()),
    Ok("john@example.com ".to_string()),
    Ok("for help".to_string()),
]);

let results: Vec<_> = streaming.redact_stream(chunks).collect().await;
```

### CLI Tool

```bash
# Build the CLI
cargo build --package auvura-cli

# Redact PII from a string
auvura redact --text "Contact john@example.com or call 123-456-7890"
# Output: Contact ████.███@███████.com or call ███-███-████

# Redact PII from a file
auvura redact --file document.txt

# Redact from stdin (pipe)
echo "My SSN is 123-45-6789" | auvura redact

# Redact with JSON output
auvura redact --text "Email: test@example.com" --format json

# Validate (detect PII without redacting)
auvura validate --text "Send docs to alice@company.com"
# Output:
# Found 1 PII detection(s):
#   email at byte 15..35: "alice@company.com"
#
# Redacted output:
# Send docs to ████@███████.com

# Validate with JSON output
auvura validate --text "SSN: 123-45-6789" --format json

# Start the proxy server
auvura serve
auvura serve --address 0.0.0.0 --port 8080

# Use a custom config file
auvura --config my-config.toml redact --text "Hello"
```

### Proxy Server

```bash
# Copy the example config
cp auvura.example.toml auvura.toml

# Set API keys (or configure in auvura.toml)
export OPENAI_API_KEY="your-key"
export ANTHROPIC_API_KEY="your-key"

# Run with default config (auvura.toml)
cargo run --package auvura-proxy

# Run with custom config and port
cargo run --package auvura-proxy -- --config my-config.toml --port 8080

# Run listening on all interfaces
cargo run --package auvura-proxy -- --address 0.0.0.0 --port 9090

# Use with any OpenAI-compatible SDK
curl http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "My email is john@example.com"}],
    "provider": "openai"
  }'

# Anthropic Claude (uses Messages API)
curl http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-sonnet-20240229",
    "messages": [{"role": "user", "content": "My email is john@example.com"}],
    "provider": "anthropic"
  }'

# Google Gemini
curl http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-pro",
    "messages": [{"role": "user", "content": "My email is john@example.com"}],
    "provider": "gemini"
  }'

# Mistral AI
curl http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-large-latest",
    "messages": [{"role": "user", "content": "My email is john@example.com"}],
    "provider": "mistral"
  }'

# Cohere
curl http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "command-r-plus",
    "messages": [{"role": "user", "content": "My email is john@example.com"}],
    "provider": "cohere"
  }'

# Azure OpenAI
curl http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "My email is john@example.com"}],
    "provider": "azure"
  }'

# Ollama (local inference)
curl http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3",
    "messages": [{"role": "user", "content": "My email is john@example.com"}],
    "provider": "ollama"
  }'

# SSE streaming endpoint (real-time token-by-token response)
curl -N http://localhost:3000/v1/chat/completions/stream \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "My email is john@example.com"}],
    "provider": "openai"
  }'
```

### How Streaming PII Reconstruction Works

The streaming endpoint uses **token markers** to enable real-time PII reconstruction:

1. **Redact**: `john@example.com` → `[[PII_0]]`
2. **Inject system message**: Tells the LLM "Use `[[PII_0]]` in your response — it will be reconstructed"
3. **LLM responds**: `"I'll send details to [[PII_0]]."`
4. **Reconstruct**: `[[PII_0]]` → `john@example.com` in each stream chunk

The client receives the reconstructed text in real-time. The actual PII never leaves your environment — only the token markers are sent to the provider.

## Compliance Profiles

| Profile | Enabled Types | Use Case |
|---------|----------------|----------|
| `default()` | All types | General purpose |
| `gdpr()` | Email, Phone, IPv4, IPv6 | EU privacy regulation |
| `hipaa()` | SSN, Phone, IPv4 + allowlist | US health data |
| `pci_dss()` | Credit Card (strict validation) | Payment processing |

## Detection Types

| Type | Config Key | Format | Example Redacted |
|------|-----------|--------|-----------------|
| Email | `email` | `user@domain.tld` | `████.███@███████.com` |
| Phone | `phone` | Various intl formats | `(███) ███-████` |
| SSN | `ssn` | `###-##-####` | `███-██-████` |
| Credit Card | `credit_card` | `#### #### #### ####` | `████ ████ ████ 1111` |
| IPv4 | `ipv4` | `192.168.1.1` | `█████████████` |
| IPv6 | `ipv6` | `::ffff:192.168.1.1` | `██████████████████████` |
| IBAN | `iban` | `DE89 3704 0044 0532 0130 00` | `DE████████████████30 00` |
| Passport | `passport` | `AB1234567` | `AB███████` |
| National ID | `national_id` | Various country formats | `████████████` |
| Physical Address | `address` | Street, City, State ZIP | `████████████████` |

### Phone Country Configuration

Phone detection supports a configurable country priority list. By default, it validates against **7 countries**: US, GB, DE, FR, CA, AU, JP.

In `auvura.toml`:

```toml
[policy]
phone_countries = ["DE", "FR", "JP"]  # Only detect DE, FR, JP numbers
```

Via code:

```rust
let detector = PhoneNumberDetector::with_countries(vec!["DE".into(), "FR".into()]);
```

Numbers with international prefix (`+`) are always validated via phonelib regardless of the country list.

### Policy Configuration

Enable or disable specific PII types in `auvura.toml`:

```toml
[policy]
enabled_types = ["email", "phone_number", "credit_card", "iban", "passport"]
```

Valid config keys: `email`, `phone`/`phone_number`, `ssn`, `credit_card`, `ipv4`/`ip_address_v4`, `ipv6`/`ip_address_v6`, `iban`, `passport`/`passport_number`, `national_id`, `address`/`physical_address`.

When `enabled_types` is omitted or empty, all types are enabled by default.

### CORS Configuration

CORS support is available for browser-based SDK integrations. It is **disabled by default** — when no `[cors]` section is present, no `Access-Control-*` headers are sent.

In `auvura.toml`:

```toml
[cors]
allowed_origins = ["https://app.example.com"]  # Required to enable CORS
allowed_methods = ["POST", "OPTIONS"]          # Default if omitted
allowed_headers = ["Content-Type", "Authorization"]  # Default if omitted
allow_credentials = false                       # Default if omitted
max_age = 3600                                  # Preflight cache seconds (optional)
```

Use `allowed_origins = ["*"]` to allow all origins (not recommended for production).

### Rate Limiting

Per-IP rate limiting protects against abuse. Disabled by default.

In `auvura.toml`:

```toml
[rate_limit]
requests_per_second = 10    # Max requests per second per IP
burst_size = 10             # Max concurrent requests in a burst
```

Uses a token bucket algorithm: each IP gets a bucket that refills at `requests_per_second` tokens/sec, up to `burst_size` capacity. Over-limit requests receive `429 Too Many Requests`.

### Authentication

API key authentication protects the proxy from unauthorized access. **Disabled by default** — anyone on the network can use the proxy.

When enabled, clients must include a valid API key in the `Authorization` header:
```
Authorization: Bearer <api-key>
```

In `auvura.toml`:

```toml
[auth]
enabled = true

[[auth.api_keys]]
value = "your-secret-api-key"  # Direct value (not recommended for production)

[[auth.api_keys]]
env = "PROXY_API_KEY"          # Read from environment variable (recommended)
```

Features:
- Multiple API keys supported
- Keys can be literal values or environment variable references
- Health endpoint (`/health`) is always accessible without authentication
- Returns `401 Unauthorized` with `WWW-Authenticate: Bearer` header on failure

### Request Size Limits

Maximum request body size defaults to **10 MB**. Set to `0` to disable.

```toml
[request_limit]
max_body_bytes = 10485760   # 10 MB (default)
```

Oversized payloads receive `413 Payload Too Large`.

### Audit Logging

Structured audit logging for GDPR/HIPAA compliance. Records detection and redaction events with timestamps, PII types, and redacted forms. **Disabled by default**.

In `auvura.toml`:

```toml
[audit]
enabled = true
destination = "stdout"   # "stdout" (default) or "file"
# file_path = "/var/log/auvura/audit.jsonl"  # Only used when destination is "file"
```

When enabled, each redaction request logs:
- **Detection events**: PII type, confidence level, byte offsets, redacted form
- **Request events**: Whether PII was found, detection count, whether redaction occurred

Example output:
```json
{"timestamp":"2024-01-15T10:30:00Z","event":"detection","pii_type":"email","confidence":"medium","start":15,"end":35,"original_len":20,"redacted_form":"████.███@███████.com"}
{"timestamp":"2024-01-15T10:30:00Z","event":"request_processed","had_pii":true,"detection_count":1,"redacted":true}
```

For production, implement the `AuditLogger` trait to send events to your logging infrastructure.

## How It Works

1. **Detection**: Regex-based detectors find PII patterns in text
2. **Validation**: Luhn checks (credit cards), SSA rules (SSN), phonelib (phones)
3. **Priority Resolution**: Higher priority PII types win on overlaps (SSN > CreditCard > Phone > Email)
4. **Structured Redaction**: Format-preserving masks (show last 4 for credit cards)
5. **Multi-Message Support**: All PII-containing messages are redacted and reconstructed (not just the last one)
6. **Zero-Copy Optimization**: `Cow<str>` avoids allocations when no PII found

## Security

- **Memory Safety**: `zeroize` crate ensures detection data is erased from memory on drop
- **Local-First**: Proxy redacts data before it leaves your environment
- **No False Negatives**: Strict validation mode ensures high precision

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check — returns `{"status":"ok"}` |
| `GET` | `/metrics` | Prometheus metrics endpoint |
| `GET` | `/v1/models` | List available models (OpenAI-compatible) |
| `POST` | `/v1/chat/completions` | OpenAI-compatible chat completions |
| `POST` | `/v1/chat/completions/stream` | SSE streaming chat completions |

## Testing

```bash
# Run all tests (400+ tests)
cargo test --workspace

# Run unit tests only
cargo test -p auvura-core
cargo test -p auvura-proxy
cargo test -p auvura-cli

# Run integration tests
cargo test -p auvura-tests

# Run benchmarks
cargo bench -p auvura-core --bench redaction_benchmarks

# Run fuzz targets (requires nightly + cargo-fuzz)
cargo +nightly fuzz run fuzz_redactor
cargo +nightly fuzz run fuzz_json_redactor
cargo +nightly fuzz run fuzz_detectors
```

Test coverage includes:
- **Unit tests**: PII detectors, redactor, policy, JSON redaction, streaming redaction, provider adapters (223 core + 91 proxy + 16 CLI)
- **Integration tests**: End-to-end redaction pipeline, JSON structure preservation, streaming, policy round-trips, edge cases (86 tests in `auvura-tests`)
- **Fuzz targets**: Redactor, JSON redactor, individual detectors — test for panics and invalid output on arbitrary input
- **Benchmarks**: Detection speed, redaction throughput, JSON redaction, no-PII passthrough

## Status

- [x] Core PII detection library
- [x] Email, Phone, SSN, Credit Card detectors
- [x] IPv4/IPv6 detectors
- [x] IBAN detector with mod-97 checksum validation
- [x] Passport number detector (multiple country formats)
- [x] National ID detector (Aadhaar, PAN, TFN, INSEE)
- [x] Physical address detector (street, city, state, ZIP)
- [x] Compliance policy profiles (GDPR, HIPAA, PCI-DSS)
- [x] Structured redaction engine
- [x] Provider-agnostic proxy with OpenAI-compatible API
- [x] SSE streaming endpoint with real-time PII reconstruction
- [x] NER module (`SimpleNameDetector`, `TokenRedactor`)
- [x] Aho-Corasick multi-pattern optimization for `MultiDetector`
- [x] Proxy configuration via TOML file + CLI args
- [x] Multiple provider adapters (OpenAI, Anthropic, Gemini, Mistral, Cohere, Azure, Bedrock, Ollama)
- [ ] BERT-based NER (`ner` feature flag — placeholder)
- [x] CLI binary (`redact`, `validate`, `serve`)
- [x] JSON-structure-aware redaction (`JsonRedactor`)
- [x] Streaming redaction API (`StreamingRedactor`, `RedactorStreamExt`)
- [x] Configurable phone country list
- [x] CORS support
- [x] Per-IP rate limiting
- [x] Request size limits
- [x] Graceful shutdown (SIGTERM/SIGINT handling, in-flight requests complete)
- [x] Structured logging with `tracing` (log levels, request tracing, env-filter)
- [x] Metrics & observability with Prometheus exporter (request count, latency, PII detection rates)
- [x] Confidence scoring for detections (High/Medium/Low)
- [x] Structured audit logging for GDPR/HIPAA compliance
- [x] Integration test suite (86 tests across 5 test files)
- [x] Criterion benchmarks (8 benchmarks)
- [x] Fuzz targets (3 targets: redactor, JSON redactor, detectors)
- [ ] Quoted email local parts (V2)
- [ ] Performance benchmarking

## How to Contribute

We welcome contributions! Here's how to get started:

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/auvura.git
cd auvura

# Build the project
cargo build --workspace

# Run tests
cargo test --workspace

# Run linter
cargo clippy --workspace

# Run formatter check
cargo fmt --workspace --check
```

### Branch Naming Convention

We use conventional branch prefixes:
- `feat/` - New features
- `fix/` - Bug fixes
- `refactor/` - Code refactoring
- `chore/` - Maintenance tasks
- `docs/` - Documentation updates
- `test/` - Adding or updating tests

Examples:
- `fix/email/invalid-regex`
- `feat/proxy/anthropic-support`
- `refactor/core/reduce-allocations`

### Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>
```

Examples:
- `fix(credit_card): correct Mastercard BIN range validation`
- `feat(proxy): add OpenAI-compatible endpoint`
- `refactor(detector): reduce cloning in overlap resolution`
- `docs(readme): update usage examples`

### Pull Request Process

1. Fork the repository
2. Create your feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'feat(scope): add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

### Adding a New Detector

1. Create a new file in `crates/auvura-core/src/detectors/`
2. Implement the `PiiDetector` trait
3. Add module declaration in `mod.rs`
4. Add comprehensive tests
5. Update compliance profiles in `policy.rs` if needed

### Code Review Checklist

- [ ] All tests pass (`cargo test --workspace`)
- [ ] No clippy warnings (`cargo clippy --workspace`)
- [ ] Code is formatted (`cargo fmt --workspace`)
- [ ] Documentation updated (if needed)
- [ ] Tests added for new functionality
- [ ] Breaking changes documented

## License

Apache-2.0
