# Roadmap

## Features

- **Complete Factor Implementation**: Not all proposed MFKDF2 factors have been implemented (e.g., fuzzy encryption, QR,  etc.).
- **Architecture modifications**: Current architecture mirrors JS reference, and should be moved to natural rust architecture.
  - Builder pattern for factor (setup, derive) construction
  - Uniffi custom types
  - Binding functions shim as a separate module
  - left todos in the codebase
- **Complete Language Bindings**: While the framework is in place, bindings for languages like Python, Kotlin, Swift, and Go are not yet complete.
- **`no_std` support**: Enable running MFKDF2 on embedded devices.
- **Benchmarks and examples/tutorials**: Add comprehensive usage examples and benchmarks to demonstrate performance and guide new users.

## Potential Security Issues

- Usage of Node native WebCrypto APIs in the reference and deviations from RFC behavior, e.g., [`subtle.exportKey`](https://nodejs.org/api/webcrypto.html#subtleexportkeyformat-key).
- No explicit zeroization of sensitive memory on drop.
- Lack of constant‑time implementations for side‑channel resistance in some paths.
- Uninitialized fields in some factors (e.g., entropy, params).
- See also: [`SECURITY.md`](../../SECURITY.md) for broader issues identified across dependent crates and components.

