# MFKDF2

The Next-Generation Multi-Factor Key Derivation Function (MFKDF2) is a function that takes multiple inputs and outputs a string of bytes that can be used as a cryptographic key. It serves the same purpose as a password-based key derivation function (PBKDF), but is stronger than password-based key derivation due to its support for multiple authentication factors, including HOTP, TOTP, and hardware tokens like YubiKey. MFKDF2 also enables self-service account recovery via K-of-N (secret-sharing style) key derivation, eliminating the need for central recovery keys, and supports arbitrarily complex key derivation policies. It builds on the now-deprecated original MFKDF.

This is the rust implementation of MFKDF2, with focus on security, performance and extensibility to other languages.

# Next steps
- [ ] factor setup and derive
- [ ] Policy, stack, reconstitute
- [ ] complete tests
  - setup
  - derive pass/fail
  - threshold setup/derive
- [ ] differential test with mfkdf2.js reference implementation
- [ ] other language bindings: python, kotlin, swift, golang

## Uniffi

For other bindings, we can run:
```bash
cargo run --bin uniffi-bindgen generate --library target/debug/libmfkdf2.dylib --language python --out-dir out
```

For ts bindings, follow:
- Make sure npm is installed.
- generate bindings using `just gen-ts-bindings`
- run to test bindings: `just test-bindings`