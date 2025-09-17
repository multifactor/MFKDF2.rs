# MFKDF2 Web

TypeScript/JavaScript bindings for MFKDF2 (Multi-Factor Key Derivation Function v2), built with UniFFI.

## Overview

This package provides web-compatible APIs for MFKDF2, allowing you to use multi-factor key derivation in browser and Node.js environments. The bindings are automatically generated from the Rust implementation using UniFFI, ensuring type safety and performance.

## Features

- **Multi-Factor Authentication**: Combine multiple authentication factors (passwords, HOTP, questions, etc.)
- **Type-Safe APIs**: Full TypeScript support with generated type definitions
- **Cross-Platform**: Works in browsers, Node.js, and React Native environments
- **Zero-Copy Performance**: Direct bindings to Rust implementation via WebAssembly

## Installation

```bash
npm install mfkdf2-web
```

## Quick Start

```typescript
import { setupKey, deriveKey } from 'mfkdf2-web';

// Setup a key with multiple factors
const setup = await setupKey({
  factors: [
    { type: 'password', password: 'mySecretPassword' },
    { type: 'hotp', secret: 'JBSWY3DPEHPK3PXP' }
  ]
});

// Later, derive the same key using the factors
const derived = await deriveKey({
  policy: setup.policy,
  factors: [
    { type: 'password', password: 'mySecretPassword' },
    { type: 'hotp', secret: 'JBSWY3DPEHPK3PXP', counter: 0 }
  ]
});

console.log(derived.key === setup.key); // true
```

## Architecture

The TypeScript APIs are automatically generated from the Rust implementation:

- **Rust Core** (`../mfkdf2/`) - Core MFKDF2 implementation
- **UniFFI Interface** - Defines the public API surface
- **Generated Bindings** (`src/generated/`) - Auto-generated TypeScript types and functions
- **Web Wrapper** (`src/index.ts`) - Web-optimized API layer

This ensures the JavaScript/TypeScript APIs stay in sync with the Rust implementation while providing idiomatic web APIs.
