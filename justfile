default:
    @just --list

[private]
warn := `printf '\x1b[33m'`
error := `printf '\x1b[31m'`
info := `printf '\x1b[34m'`
success := `printf '\x1b[32m'`
reset := `printf '\x1b[0m'`
bold := `printf '\x1b[1m'`

# Print formatted headers without shell scripts
[private]
header msg:
    @printf "{{info}}{{bold}}==> {{msg}}{{reset}}\n"

# Install cargo tools
install-tools:
    if ! command -v taplo > /dev/null; then \
        printf "{{info}}Installing taplo...{{reset}}\n" && \
        cargo install taplo-cli; \
    else \
        printf "{{success}}✓ taplo already installed{{reset}}\n"; \
    fi

# Install rust toolchain
install-rust:
    @just header "Installing Rust Toolchain"
    rustup install

# Setup complete development environment
setup: install-tools install-rust
    @printf "{{success}}{{bold}}Development environment setup complete!{{reset}}\n"

# Check the with local OS target
check:
    @just header "Building workspace"
    cargo build --workspace --all-targets

# Run the tests on your local OS
test:
    @just header "Running main test suite"
    cargo test --workspace --all-targets --all-features
    @just header "Running doc tests"
    cargo test --workspace --doc

# Run clippy for the workspace on your local OS
lint:
    @just header "Running clippy"
    cargo clippy --workspace --all-targets --all-features

# Run format for the workspace
fmt:
    @just header "Formatting code"
    cargo fmt --all
    taplo fmt

# Run cargo clean to remove build artifacts
clean:
    @just header "Cleaning build artifacts"
    cargo clean

# Open cargo docs in browser
docs:
    @just header "Building and opening cargo docs"
    cargo doc --workspace --no-deps --open

doc-check:
    @just header "Checking cargo docs"
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Show your relevant environment information
info:
    @just header "Environment Information"
    @printf "{{info}}OS:{{reset}} %s\n" "$(uname -s)"
    @printf "{{info}}Rust:{{reset}} %s\n" "$(rustc --version)"
    @printf "{{info}}Cargo:{{reset}} %s\n" "$(cargo --version)"
    @printf "{{info}}Installed targets:{{reset}}\n"
    @rustup target list --installed | sed 's/^/  /'

# Run all possible CI checks (cannot test a non-local OS target!)
ci:
    @printf "{{bold}}Starting CI checks{{reset}}\n\n"
    @ERROR=0; \
    just run-single-check "Rust formatting" "cargo fmt --all -- --check" || ERROR=1; \
    just run-single-check "TOML formatting" "taplo fmt --check" || ERROR=1; \
    just run-single-check "Check" "cargo check --workspace" || ERROR=1; \
    just run-single-check "Clippy" "cargo clippy --workspace --all-targets --all-features -- --deny warnings" || ERROR=1; \
    just run-single-check "Test suite" "cargo test --verbose --workspace" || ERROR=1; \
    just run-single-check "Doc check" "RUSTDOCFLAGS=\"-D warnings\" cargo doc --no-deps --all-features" || ERROR=1; \
    printf "\n{{bold}}CI Summary:{{reset}}\n"; \
    if [ $ERROR -eq 0 ]; then \
        printf "{{success}}{{bold}}All checks passed successfully!{{reset}}\n"; \
    else \
        printf "{{error}}{{bold}}Some checks failed. See output above for details.{{reset}}\n"; \
        exit 1; \
    fi

# Run a single check and return status (0 = pass, 1 = fail)
[private]
run-single-check name command:
    #!/usr/bin/env sh
    printf "{{info}}{{bold}}Running{{reset}} {{info}}%s{{reset}}...\n" "{{name}}"
    if {{command}} > /tmp/check-output 2>&1; then
        printf "  {{success}}{{bold}}PASSED{{reset}}\n"
        exit 0
    else
        printf "  {{error}}{{bold}}FAILED{{reset}}\n"
        printf "{{error}}----------------------------------------\n"
        while IFS= read -r line; do
            printf "{{error}}%s{{reset}}\n" "$line"
        done < /tmp/check-output
        printf "{{error}}----------------------------------------{{reset}}\n"
        exit 1
    fi

# Success summary (called if all checks pass)
[private]
_ci-summary-success:
    @printf "\n{{bold}}CI Summary:{{reset}}\n"
    @printf "{{success}}{{bold}}All checks passed successfully!{{reset}}\n"

# Failure summary (called if any check fails)
[private]
_ci-summary-failure:
    @printf "\n{{bold}}CI Summary:{{reset}}\n"
    @printf "{{error}}{{bold}}Some checks failed. See output above for details.{{reset}}\n"
    @exit 1

# Generate the TypeScript bindings
gen-ts-bindings:
    @just header "Generating TypeScript bindings"
    cd mfkdf2-web && npm i && npm run ubrn:web
    @echo "Updating index.web.ts implementation"
    @cp mfkdf2-web/src/index.ts mfkdf2-web/src/index.web.ts

verify-bindings:
    @just header "Verifying bindings"
    @if [ ! -d "mfkdf2-web/src/generated" ] || [ -z "$(ls -A mfkdf2-web/src/generated)" ]; then \
        printf "{{error}}Error: mfkdf2-web/src/generated does not exist or is empty. Run 'just gen-ts-bindings' first.{{reset}}\n"; \
        exit 1; \
    fi
    @if [ ! -d "mfkdf2-web/rust_modules" ]; then \
        printf "{{error}}Error: mfkdf2-web/rust_modules does not exist. Run 'just gen-ts-bindings' first.{{reset}}\n"; \
        exit 1; \
    fi
    @if [ ! -d "mfkdf2-web/node_modules" ]; then \
        printf "{{error}}Error: mfkdf2-web/node_modules does not exist. Run 'just gen-ts-bindings' first.{{reset}}\n"; \
        exit 1; \
    fi
    @printf "{{success}}✓ TypeScript bindings verified{{reset}}\n"

test-bindings:
    @just header "Testing TypeScript bindings"
    @just verify-bindings  # verify bindings is generated
    cd mfkdf2-web && npm test