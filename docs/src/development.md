# Development

## Repository details

The core library is written in Rust. This repository uses `just` as a command runner for common tasks.

Key repository files:

- [`README.md`](../../README.md)
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- [`SECURITY.md`](../../SECURITY.md)
- [`justfile`](../../justfile)
- Web bindings package: [`mfkdf2-web/README.md`](../../mfkdf2-web/README.md)

Install prerequisites:

```bash
# Install Rust (via rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install

# Install just
cargo install just
```

One-time project setup (installs required tools used in this repo):

```bash
just setup
```

This ensures Rust toolchains are installed and required CLI tools are available (including Node/npm checks and UniFFI tooling).

## Build and test

Build the workspace:

```bash
just check
```

Run tests:

```bash
just test
```

## Bindings

Bindings expose the Rust core to other languages (e.g., TypeScript/Web via WASM). For prerequisites, generation, verification, and testing steps, see:

- [Bindings](bindings/bindings.md)

## Test reports 

The CI pipelines publish test reports directly into the mdBook output. After a successful run of the Rust and Bindings workflows, the following report indexes are available:

- [Rust report](reports/rust/index.html)
- [Web (TS) report](reports/web/index.html)
- [Web differential report](reports/web-diff/index.html)