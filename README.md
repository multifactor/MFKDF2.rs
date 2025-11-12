[<img src="https://raw.githubusercontent.com/multifactor/MFKDF/main/logo.png" height="64">](https://mfkdf.com/ "MFKDF")

[![GitHub issues](https://img.shields.io/github/issues/multifactor/MFKDF2.rs)](https://github.com/multifactor/MFKDF2.rs/issues)
[![BSD](https://img.shields.io/badge/license-BSD-brightgreen.svg)](https://github.com/multifactor/MFKDF2.rs/blob/main/LICENSE)
![warning](https://img.shields.io/badge/warning-not_production_ready-red)

# MFKDF2: Multi-Factor Key Derivation Function

Multi-Factor Key Derivation Function (MFKDF2) is a modern, highly-secure function designed to derive cryptographic keys from multiple inputs, or "factors". It serves a similar purpose to traditional password-based key derivation functions (PBKDFs) like Argon2 or scrypt, but offers significantly stronger security guarantees by natively supporting a wide range of authentication factors.

This repository contains the canonical Rust implementation of MFKDF2, with a focus on security, performance, and multi-language support through generated bindings.

> [!WARNING]
> This is not production-ready. Please do not use it in production. Please report any security vulnerabilities to the project maintainers.

## Features

- **Multi-Factor Security**: Go beyond simple passwords. MFKDF2 natively supports factors like:
  - Passwords
  - HOTP (HMAC-based One-Time Password)
  - TOTP (Time-based One-Time Password)
  - Hardware tokens (e.g., YubiKey)
  - Passkey
- **Self-Service Account Recovery**: Implement K-of-N secret sharing policies, allowing users to recover accounts without centralized recovery keys.
- **Flexible Policies**: Define arbitrarily complex key derivation policies to meet your specific security requirements.
- **Cross-Language Support**: Core logic is written in Rust, with bindings for other languages like TypeScript, Python, and more.
- **Secure by Design**: Built with modern cryptographic primitives and a strong focus on security best practices.
- **Additional capabilities**:
  - Modes:
    - MFCHF (Multi-Factor Credential Hashing Function): enables server-side verification of multiple standard authentication factors simultaneously.
    - MFDPG (Multi-Factor Deterministic Password Generator): enables stateless password managers and client-side MFA for password-only sites.
  - Derived-key capabilities:
    - Strengthening: increase KDF cost over time without changing the enveloped key.
    - Reconstitution: replace lost or compromised factors without altering the final key.
    - Persistence: optionally persist factor material to bypass that factor in future derivations.
    - Hints: provide low-entropy hints to help identify the correct factor.
  - Entropy: derived-key entropy estimation via Dropbox's zxcvbn
- **Comprehensive Testing and Differential Validation**: Includes rigorous test coverage and differential testing to verify correctness by comparing against the canonical JavaScript reference implementation.

## Roadmap

For this library to be considered fully production-ready, the following items should be addressed:

- **Complete Factor Implementation**: Not all proposed MFKDF2 factors have been implemented (e.g., fuzzy encryption, QR,  etc.).
- **Architecture modifications**: Current architecture mirrors JS reference, and should be moved to natural rust architecture.
  - Builder pattern for factor (setup, derive) construction
  - Uniffi custom types
  - Binding functions shim as a separate module
  - left todos in the codebase
- **Complete Language Bindings**: While the framework is in place, bindings for languages like Python, Kotlin, Swift, and Go are not yet complete.
- **Documentation**: Detailed documentation and usage examples have not been set up yet.
- **Detailed `CONTRIBUTING.md`**: A more detailed guide for contributors.
- **Formal Security Audit**: The library has not yet undergone a formal, third-party security audit.

## Project Layout

This repository is structured as a workspace with several crates:

- `mfkdf2`: The core Rust library containing the MFKDF2 implementation.
  - `derive`: factor derive construction
  - `setup`: factor setup construction
  - `definitions`: necessary types required for MFKDF2 key derivation
  - `policy`: MFKDF2 policy construction
  - `crypto`: utility cryptography module
  - `integrity`: MFKDF2 policy integrity using HMAC construction
- `mfkdf2-web`: TypeScript/WASM bindings for use in web browsers and Node.js.
- `mfkdf2-py`: Python bindings for the core library.

## Installation

To use `mfkdf2` in your Rust project, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
mfkdf2 = { version = "0.1.0", git = "https://github.com/multifactor/mfkdf2.rs.git" }
```

This will be updated to a published version once the library is ready for production.

## Setup

1. Make sure [rust](https://rust-lang.org/tools/install) is installed.
2. We use [just](https://github.com/casey/just#cross-platform) for managing project specific build commands.
3. TS Bindings require [npm](https://nodejs.org/en/download/) to be installed

### Bindings

This library uses [UniFFI](https://mozilla.github.io/uniffi-rs/) to generate bindings for other languages.

**TypeScript/WASM:**

1.  Ensure you have the `wasm32-unknown-unknown` Rust toolchain installed:
    ```bash
    rustup target add wasm32-unknown-unknown
    ```
2.  Generate the bindings:
    ```bash
    just gen-ts-bindings
    ```
3.  Run tests to verify the bindings:
    ```bash
    just test-bindings
    ```

See more details in the [mfkdf2-web README](mfkdf2-web/README.md).

**Python:**

To generate Python bindings, run the following command:

```bash
cargo run --bin uniffi-bindgen generate --library target/debug/libmfkdf2.dylib --language python --out-dir mfkdf2-py/src
```

## Usage

```rust
use std::collections::HashMap;
use mfkdf2::{derive, setup};
use mfkdf2::setup::{factors::hotp::HOTPOptions, password::PasswordOptions, key::MFKDF2Options};
use mfkdf2::derive::factors::{hotp::HOTPOptions, password::PasswordOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Define factors
    let password_factor = setup::password("my-super-secret-password", PasswordOptions::default())?;
    let totp_factor = setup::hotp("base32-encoded-secret", HOTPOptions::default())?;

    // 2. Set up the key with the policy
    let key = setup::key(vec![password_factor, totp_factor], MFKDF2Options::default())?;

    println!("Key: {:?}", key);

    let factors = HashMap::from([
      ("password".to_string(), derive::factors::password("my-super-secret-password")?),
      "hotp".to_string(), derive::factors::hotp("123456")?),
    ]);
    // 3. Derive the key using user inputs
    let derived_key = derive::key(key.policy, factors, true, false)?;

    println!("Derived Key: {:?}", derived_key);

    Ok(())
}
```

## Development

This project uses [just](https://github.com/casey/just#cross-platform) for managing project-specific build commands. To install just, run:

```bash
cargo install just
```

### Quick Start

```bash
# Install all development dependencies (Rust tools, UniFFI, Node.js packages)
just setup

# See all available commands
just

# Run the full CI pipeline locally
just ci
```

### Common Commands

- `just check` - Build the workspace
- `just test` - Run all tests
- `just lint` - Run clippy linting
- `just udeps` - Check for unused dependencies
- `just fmt` - Format code (Rust + TOML)
- `just gen-ts-bindings` - Generate TypeScript bindings
- `just verify-bindnigs` - Verify that bindings were properly generated
- `just test-bindings` - Test the TypeScript bindings

## License

This project is licensed under the Clear BSD License. See the [LICENSE](LICENSE) file for details.

## Contributing

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for details.

## Security

See the [SECURITY.md](SECURITY.md) file for details.