# Benchmarks

MFKDF2 includes a comprehensive set of benchmarks using [Criterion.rs](https://github.com/bheisler/criterion.rs) to measure performance of various operations.

## Prerequisites

- Rust toolchain installed
- The `mfkdf2` crate dependencies (installed automatically when running benchmarks)

## Running Benchmarks

### Run All MFKDF2 Benchmarks

```bash
cargo bench -p mfkdf2
```

This will run all benchmark suites and generate HTML reports.

### Run Specific Benchmark Suites

Run individual benchmark files:

```bash
# Single factor operations
cargo bench -p mfkdf2 --bench password

# Single factor setup operation
cargo bench -p mfkdf2 --bench password -- single_setup

# Multi-factor combinations (setup + derive)
cargo bench -p mfkdf2 --bench factor_combination

# Password derivation from derived keys
cargo bench -p mfkdf2 --bench mfdpg

# Key reconstitution operations
cargo bench -p mfkdf2 --bench reconstitution
```

### Deterministic Benchmarks

For reproducible benchmark results, use the `differential-test` feature flag which enables deterministic RNG:

```bash
cargo bench -p mfkdf2 --features differential-test
```

## Benchmark Suites

The benchmarks are now organized by factor type. Each factor has its own benchmark suite containing five benchmark functions:

- `single_setup`: Setup operation with a single factor
- `single_derive`: Derive operation with a single factor
- `multiple_setup_3_threshold_3`: Setup with 3 factors requiring all 3 (threshold = 3)
- `multiple_derive_3`: Derive with all 3 factors (meets threshold = 3 requirement)
- `threshold_derive_2_of_3`: Derive with 2 factors (meets threshold = 2 requirement)

### Available Factor Benchmarks

The benchmarks cover all supported MFKDF2 factor types. Each factor type has its own dedicated benchmark suite that can be run individually using `cargo bench -p mfkdf2 --bench [factor_name]`.

On an Apple M1-Pro:

| factor   | single_setup | single_derive | multiple_setup | multiple_derive (3 of 3) | multiple_derive (2 of 3) |
| -------- | ------------ | ------------- | -------------- | ------------------------ | ------------------------ |
| hmacsha1 | 14.8ms       | 14.8ms        | 14.9ms         | 14.8ms                   | 14.9ms                   |
| hotp     | 14.8ms       | 14.9ms        | 15.0ms         | 15.2ms                   | 15.2ms                   |
| ooba     | 146ms        | 15.0ms        | 426ms          | 15.3ms                   | 15.2ms                   |
| passkey  | 14.9ms       | 14.8ms        | 14.8ms         | 14.8ms                   | 14.8ms                   |
| password | 14.9ms       | 14.9ms        | 15.1ms         | 15.1ms                   | 15.0ms                   |
| question | 14.9ms       | 14.9ms        | 15.0ms         | 14.9ms                   | 14.9ms                   |
| stack    | 15.8ms       | 15.5ms        | 15.8ms         | 15.9ms                   | 15.3ms                   |
| totp     | 16.2ms       | 49.6ms        | 19.0ms         | 19.1ms                   | 17.8ms                   |
| uuid     | 14.8ms       | 14.9ms        | 14.9ms         | 14.8ms                   | 14.9ms                   |

### Password Derivation Benchmark

The `mfdpg` benchmark suite measures the performance of password derivation from already-derived MFKDF2 keys using regex patterns. This benchmarks the `derive_password` method on `MFKDF2DerivedKey` with different regex complexity levels:

- `derive_password_simple`: Tests with `[a-zA-Z0-9]{8}` pattern (alphanumeric, fixed length)
- `derive_password_medium`: Tests with `[a-zA-Z]{6,10}` pattern (alphabetic, variable length)
- `derive_password_complex`: Tests with complex regex `([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*` (structured pattern)
- `derive_password_digits_only`: Tests with `[0-9]{6}` pattern (digits only)
- `derive_password_long`: Tests with `[a-zA-Z0-9]{16}` pattern (longer password)

Run the password derivation benchmarks with:

```bash
cargo bench -p mfkdf2 --bench mfdpg
```

### Key Reconstitution Benchmark

The `reconstitution` benchmark suite measures the performance of key reconstitution operations on already-derived MFKDF2 keys. These operations allow modifying the key structure after initial setup:

- `set_threshold_3_to_2`: Changes the threshold from 3 to 2 factors on a 3-factor key
- `add_2_factors`: Adds 2 new password factors to an existing key
- `remove_2_factors`: Removes 2 factors from an existing key

Run the key reconstitution benchmarks with:

```bash
cargo bench -p mfkdf2 --bench reconstitution
```

## Viewing Results

After running benchmarks, Criterion generates HTML reports in:
- `target/criterion/[bench_name]/report/index.html` - Individual benchmark reports

Open these files in your web browser to view detailed performance charts and statistics.

## Interpreting Results

- **Lower is better**: Most benchmarks measure time per operation
- **Statistical analysis**: Criterion provides confidence intervals and statistical significance tests
- **Baseline comparisons**: Use `--save-baseline` and `--baseline` flags to compare performance changes

## Notes

- Benchmarks use fixed secrets and parameters to minimize variance
- RSA key generation for OOBA factors happens once per benchmark file to avoid skewing per-iteration costs
- Argon2 parameters use default settings (time=0, memory=0) for faster execution while testing the core MFKDF2 logic
