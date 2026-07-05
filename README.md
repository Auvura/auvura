# Auvura

**High-performance, local-first PII-Shield for LLMs. Built in Rust.**

Auvura is a Rust workspace that provides **PII (Personally Identifiable Information) detection and redaction** for AI applications. It acts as a security layer that ensures sensitive data never leaves your local environment when interacting with cloud AI providers.

## Features

- ** PII Detection**: Email, Phone Number, SSN, Credit Card, IP Address
- **Compliance-Ready**: GDPR, HIPAA, PCI-DSS profiles included
- **Structured Redaction**: Preserves format while masking sensitive data
- **Memory Safe**: Uses `zeroize` crate to securely erase detections from memory
- **Provider-Agnostic Proxy**: OpenAI-compatible endpoint that forwards to any AI provider
- **High Performance**: Built in Rust with zero-copy optimizations

## Project Structure

```
auvura/
├── crates/
│   ├── auvura-core/          # Core PII detection library
│   │   └── src/
│   │       ├── types.rs        # PII type definitions with regulatory basis
│   │       ├── detector.rs     # Detector trait + MultiDetector
│   │       ├── policy.rs       # Redaction policies + compliance profiles
│   │       ├── redactor.rs     # Core redaction engine
│   │       └── detectors/      # Individual detectors
│   │           ├── email.rs
│   │           ├── phone_number.rs
│   │           ├── ssn.rs
│   │           └── credit_card.rs
│   ├── auvura-cli/          # CLI binary (redact, validate, serve)
│   └── auvura-proxy/        # Proxy server for AI API redaction
│       └── src/
│           ├── main.rs        # Axum server with /v1/chat/completions
│           ├── config.rs      # TOML config + CLI arg parsing
│           └── provider.rs     # Provider-agnostic adapter system
└── Cargo.toml                   # Workspace configuration
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

| Type | Format | Example Redacted |
|------|--------|-----------------|
| Email | `user@domain.tld` | `████.███@███████.com` |
| Phone | Various intl formats | `(███) ███-████` |
| SSN | `###-##-####` | `███-██-████` |
| Credit Card | `#### #### #### ####` | `████ ████ ████ 1111` |
| IPv4 | `192.168.1.1` | `█████████████` |
| IPv6 | `::ffff:192.168.1.1` | `██████████████████████` |

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

### Request Size Limits

Maximum request body size defaults to **10 MB**. Set to `0` to disable.

```toml
[request_limit]
max_body_bytes = 10485760   # 10 MB (default)
```

Oversized payloads receive `413 Payload Too Large`.

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
| `POST` | `/v1/chat/completions` | OpenAI-compatible chat completions |
| `POST` | `/v1/chat/completions/stream` | SSE streaming chat completions |

## Testing

```bash
# Run all tests (215+ tests)
cargo test --workspace

# Run proxy tests only (unit + integration)
cargo test --package auvura-proxy

# Run core library tests only
cargo test --package auvura-core
```

Test coverage includes:
- **Core**: PII detectors (email, phone, SSN, credit card, IPv4/IPv6), redactor, policy, custom placeholders
- **Proxy**: Provider adapters (OpenAI, Anthropic), HTTP handler integration tests (via `tower::ServiceExt` + `wiremock`), `StreamCleanup` lifecycle, `mask_original` edge cases

## Status

- [x] Core PII detection library
- [x] Email, Phone, SSN, Credit Card detectors
- [x] Compliance policy profiles (GDPR, HIPAA, PCI-DSS)
- [x] Structured redaction engine
- [x] Provider-agnostic proxy with OpenAI-compatible API
- [x] SSE streaming endpoint with real-time PII reconstruction
- [x] NER module (`SimpleNameDetector`, `TokenRedactor`)
- [x] IPv4/IPv6 detectors
- [x] Aho-Corasick multi-pattern optimization for `MultiDetector`
- [x] Proxy configuration via TOML file + CLI args
- [ ] BERT-based NER (`ner` feature flag — placeholder)
- [x] CLI binary (`redact`, `validate`, `serve`)
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
