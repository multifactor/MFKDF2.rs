# Bindings

Bindings enable using the Rust core library from other languages and runtimes. This repository currently emphasizes TypeScript/Web (WASM) bindings and includes scaffolding for additional languages.

## Purpose

- Deliver a uniform, statically-typed interface to the MFKDF2 core, enabling consistent integration across ecosystems.
- Leverage the thoroughly reviewed and highly performant Rust implementation to prevent redundant logic and ensure reliability across language boundaries.
- Rely on the proven, security-focused Rust cryptography ecosystem to provide robust and trustworthy cryptographic operations.

## Bindings architecture

### High‑level overview

- UniFFI defines the foreign function interface (FFI) surface for the Rust core. Public structs, enums, and methods that are part of the cross‑language API are exposed through UniFFI so they can be consumed by generated bindings.
- Currently, TypeScript bindings are supported. To match the structure and ergonomics of the reference API, an API facade in the web package bridges between end‑user TypeScript and Rust/FFI types: see [`mfkdf2-web/src/api.ts`](../../../mfkdf2-web/src/api.ts).

Conceptually, the flow is:

1. Rust core types and functions are marked for export through UniFFI.
2. Code generation produces language bindings and low‑level glue (plus wasm-bindgen for WebAssembly targets).
3. The TypeScript facade (`mfkdf2-web/src/api.ts`) presents a stable, user‑friendly API that mirrors the reference implementation while delegating to the generated layer.

More details about FFI layer can be found at uniffi [documentation](https://mozilla.github.io/uniffi-rs/latest/).

### Facade responsibilities

The TypeScript facade is intentionally thin but provides:
- Shape adaptation: Maps idiomatic JS/TS data structures to the exact types expected by the generated FFI layer and back again.
- Naming and ergonomics: Exposes methods and parameter names that match the reference API so downstream code can remain consistent.
- Error normalization: Converts Rust errors surfaced via the generated layer into predictable JavaScript exceptions with stable messages.
- Backward compatibility: Acts as a stable contract even when low‑level Rust types evolve (within the limits of the UniFFI surface).

### What’s exported

At a high level, the exported surface includes:
- Factor setup and derive operations
- Key setup and derive operations
- Policy construction and evaluation
- Utility types and result structures returned by the operations

The facade organizes these into coherent entry points for end‑users rather than exposing granular FFI details.

### Data and serialization boundaries

- Calls from TypeScript into Rust cross a WASM + FFI boundary. Primitive values and structured data are converted into forms expected by the generated layer.
- The facade centralizes conversions to keep call‑sites clean and to ensure consistent semantics across the API.

### Extending to a new language

To introduce a new language binding:
1. Identify and confirm the UniFFI‑exported surface needed by that language.
2. Hook up the UniFFI code generation for the new target and ensure build integration.
3. Provide a small facade layer (if the target ecosystem benefits from one) to align with local conventions and the reference API’s structure.
4. Mirror the verification and testing steps used for TypeScript in that ecosystem’s test framework.

## Prerequisites

Install the following once:

```bash
# Rust toolchain
rustup install

# Project command runner
cargo install just

# Tools used by this repo (run once; installs mdBook, uniffi, etc.)
just setup
```

The setup ensures:
- `node` and `npm` are available
- `uniffi-bindgen-react-native` is installed globally via npm
- Common Rust CLI tools (`uniffi-bindgen`, `taplo-cli`, `cargo-udeps`) are installed
- `mdbook` is installed

For WebAssembly-specific builds, the workflow also uses:
- `wasm-bindgen-cli` (version pinned to 0.2.104)
- `wasm-opt` for optimization (installed via cargo wrapper when required)

## Generate bindings

TypeScript/Web (WASM) bindings are generated from the Rust core using UniFFI and wasm-bindgen. Use the provided `just` recipes:

```bash
# Debug (fast) bindings
just gen-ts-bindings-debug

# Release (optimized) bindings
just gen-ts-bindings

# Differential (release) bindings, for differential testing
just gen-ts-bindings-differential
```

These commands:
- Build the WASM crate
- Run `npm i` and bindings generation in `mfkdf2-web`
- For release builds, run `wasm-opt` and point the glue to the optimized `.wasm`

## Verify generated bindings

Before testing, verify the expected artifacts exist:

```bash
just verify-bindings
```

This checks:
- `mfkdf2-web/src/generated` contains generated sources
- `mfkdf2-web/rust_modules` is present
- `mfkdf2-web/node_modules` is installed

## Test bindings

Run the TypeScript test suite:

```bash
just test-bindings
```

To produce HTML and JUnit reports in addition to the standard output:

```bash
just test-bindings-report
```

Artifacts are written under:
- `mfkdf2-web/test-results/mochawesome/index.html` (HTML)
- `mfkdf2-web/test-results/junit/junit.xml` (JUnit)
