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
```

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
| IPv4/IPv6 | `192.168.1.1` | `█████████` |

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

## Status

- [x] Core PII detection library
- [x] Email, Phone, SSN, Credit Card detectors
- [x] Compliance policy profiles (GDPR, HIPAA, PCI-DSS)
- [x] Structured redaction engine
- [x] Provider-agnostic proxy with OpenAI-compatible API
- [ ] IPv4/IPv6 detectors
- [ ] CLI binary
- [ ] Quoted email local parts (V2)
- [ ] Performance benchmarking

## License

Apache-2.0
