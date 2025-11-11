# Differential tests

## Why differential tests? What is the scope?

The canonical JavaScript implementation of the specification is currently maintained in [MFKDF](https://github.com/multifactor/mfkdf). This repository aims to be the primary implementation written in Rust, with bindings provided to other languages and runtimes.

Development of this repository began after the MFKDF2 specification was implemented in the reference. Differential testing is used to ensure the Rust implementation is bit‑for‑bit compatible with the reference for the covered features.

Scope of differential testing:
- Exercise all supported factors for both setup and derive flows.
- Validate derived-key features (e.g., reconstitution, hints).
- Enforce policy behavior equivalence.
- For covered scenarios, MFKDF and MFKDF2.rs must produce exactly the same output bytes.

## Repositories involved in the changes

- [ssskit](https://github.com/multifactor/ssskit): Shamir secret sharing library in Rust.
- [MFKDF](https://github.com/multifactor/mfkdf): Reference JavaScript implementation.
- [randchacha](https://github.com/lonerapier/randchacha): ChaCha RNG in JavaScript for deterministic random numbers in MFKDF (fork with additional features for compatibility with Rust `ChaChaRng`).

## What changed

### MFKDF
See: [multifactor/MFKDF#27](https://github.com/multifactor/MFKDF/pull/27)
- Introduce a deterministic global RNG.
- Use the global RNG throughout factor construction, derived-key features, and Shamir share generation.
- Apply stable sorting of factor parameters for key integrity HMAC calculation.
- Use a `randchacha` fork that improves compatibility with Rust `ChaChaRng`.

### MFKDF2.rs
See: [multifactor/MFKDF2.rs#43](https://github.com/multifactor/MFKDF2.rs/pull/43)
- Add a `differential-test` feature flag providing a global deterministic RNG equivalent to the reference.
- Provide utility methods in the TypeScript bindings facade for nested parameter parsing and stringification (read/write inner params) to match reference structures.

## How to reproduce

Run the differential tests using the bindings workflow. From the repository root:

```bash
# Ensure the WASM target is present (one-time)
rustup target add wasm32-unknown-unknown

# Generate differential-release bindings (optimized)
just gen-ts-bindings-differential

# Run the TypeScript test suite (includes differential tests)
just test-bindings-differential
```

This executes the differential test suite under `mfkdf2-web/test/differential/`, validating equivalence against the reference implementation.

## What is not tested (or intentionally excluded)

- `ooba` derived key differs due to unavoidable platform/RNG differences:
  - `next`: differs because Node’s native RSA encrypt uses internal RNG.
  - `ext`: Node’s native JWK includes `ext` for browser support (not specified in the RFC).
  - `hmac`: differs due to the above fields.
- The derived-key output check for the stack factor is skipped.