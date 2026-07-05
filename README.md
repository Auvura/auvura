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
│   ├── auvura-cli/          # CLI binary (placeholder)
│   └── auvura-proxy/        # Proxy server for AI API redaction
│       └── src/
│           ├── main.rs        # Axum server with /v1/chat/completions
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
```

### Proxy Server

```bash
# Set API keys
export OPENAI_API_KEY="your-key"
export ANTHROPIC_API_KEY="your-key"

# Run proxy
cargo run --package auvura-proxy

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

## How It Works

1. **Detection**: Regex-based detectors find PII patterns in text
2. **Validation**: Luhn checks (credit cards), SSA rules (SSN), phonelib (phones)
3. **Priority Resolution**: Higher priority PII types win on overlaps (SSN > CreditCard > Phone > Email)
4. **Structured Redaction**: Format-preserving masks (show last 4 for credit cards)
5. **Zero-Copy Optimization**: `Cow<str>` avoids allocations when no PII found

## Security

- **Memory Safety**: `zeroize` crate ensures detection data is erased from memory on drop
- **Local-First**: Proxy redacts data before it leaves your environment
- **No False Negatives**: Strict validation mode ensures high precision

## Testing

```bash
# Run all tests (127+ tests)
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
- [ ] BERT-based NER (`ner` feature flag — placeholder)
- [ ] CLI binary
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
