# MFKDF2: Multi-Factor Key Derivation Function

Multi-Factor Key Derivation Function (MFKDF2) is a modern, highly-secure function designed to derive cryptographic keys from multiple inputs, or "factors". It serves a similar purpose to traditional password-based key derivation functions (PBKDFs) like Argon2 or scrypt, but offers significantly stronger security guarantees by natively supporting a wide range of authentication factors.

This repository contains the canonical Rust implementation of MFKDF2, with a focus on security, performance, and multi-language support through generated bindings.

## Features

- **Multi-Factor Security**: Go beyond simple passwords. MFKDF2 natively supports factors like:
  - Passwords
  - HOTP (HMAC-based One-Time Password)
  - TOTP (Time-based One-Time Password)
  - Hardware tokens (e.g., YubiKey)
- **Self-Service Account Recovery**: Implement K-of-N secret sharing policies, allowing users to recover accounts without centralized recovery keys.
- **Flexible Policies**: Define arbitrarily complex key derivation policies to meet your specific security requirements.
- **Cross-Language Support**: Core logic is written in Rust, with bindings for other languages like TypeScript, Python, and more.
- **Secure by Design**: Built with modern cryptographic primitives and a strong focus on security best practices.

## What's Missing

For this library to be considered fully production-ready, the following items should be addressed:

- **Complete Factor Implementation**: Not all proposed MFKDF2 factors have been implemented (e.g., `UUID`, `OOBA`, `Passkeys`).
- **Comprehensive Tests**: While basic tests are in place, more extensive testing is needed, including:
  - Differential testing against the reference JavaScript implementation.
  - Complete unit and integration tests for all factors and policies.
- **Complete Language Bindings**: While the framework is in place, bindings for languages like Python, Kotlin, Swift, and Go are not yet complete.
- **Documentation**: The `mdbook` for detailed documentation and usage examples has not been set up yet.
- **Detailed `CONTRIBUTING.md`**: A more detailed guide for contributors.
- **Formal Security Audit**: The library has not yet undergone a formal, third-party security audit.
- **Code of Conduct**: A formal Code of Conduct to foster a welcoming and inclusive community.

## Project Layout

This repository is structured as a workspace with several crates:

- `mfkdf2`: The core Rust library containing the MFKDF2 implementation.
  - `derive`: factor derive construction
  - `setup`: factor setup construction
  - `crypto`: utility cryptography module
- `mfkdf2-web`: TypeScript/WASM bindings for use in web browsers and Node.js.
- `mfkdf2-py`: Python bindings for the core library.

## Installation

To use `mfkdf2` in your Rust project, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
mfkdf2 = "0.1.0" # Replace with the latest version
```

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

**Python:**

To generate Python bindings, run the following command:

```bash
cargo run --bin uniffi-bindgen generate --library target/debug/libmfkdf2.dylib --language python --out-dir mfkdf2-py/src
```

## Usage

*Note: The following is a conceptual example. The exact API may differ.*

```rust
use mfkdf2::{Factor, Key, Policy};
use mfkdf2::factors::{Password, Totp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Define factors
    let password_factor = Password::new("my-super-secret-password", None)?;
    let totp_factor = Totp::new("base32-encoded-secret", None)?;

    // 2. Define a policy
    let policy = Policy::new(vec![
        Box::new(password_factor),
        Box::new(totp_factor),
    ]);

    // 3. Set up the key with the policy
    let key = Key::new_from_policy(&policy)?;

    // 4. Derive the key using user inputs
    let derived_key = key.derive(vec![
        "my-super-secret-password".into(),
        "123456".into(), // User-provided TOTP code
    ])?;

    println!("Derived Key: {:?}", derived_key);

    Ok(())
}
```

## API Documentation

Detailed API documentation is available on [docs.rs](https://docs.rs/mfkdf2).

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for more details on how to get involved.

## License

> [!NOTE] TODO
> add license

This project is licensed under either of:

*   Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
*   MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
