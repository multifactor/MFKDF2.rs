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
    if ! command -v cargo-udeps > /dev/null; then \
        printf "{{info}}Installing cargo-udeps...{{reset}}\n" && \
        cargo install cargo-udeps; \
    else \
        printf "{{success}}✓ cargo-udeps already installed{{reset}}\n"; \
    fi
    if ! command -v uniffi-bindgen > /dev/null; then \
        printf "{{info}}Installing uniffi-bindgen...{{reset}}\n" && \
        cargo install uniffi-bindgen; \
    else \
        printf "{{success}}✓ uniffi-bindgen already installed{{reset}}\n"; \
    fi
    if ! command -v mdbook > /dev/null; then \
        printf "{{info}}Installing mdBook...{{reset}}\n" && \
        cargo install mdbook; \
    else \
        printf "{{success}}✓ mdBook already installed{{reset}}\n"; \
    fi

# Install rust toolchain
install-rust:
    @just header "Installing Rust Toolchain"
    rustup install
    rustup target add wasm32-unknown-unknown

# Install uniffi and Node.js dependencies
install-uniffi-deps:
    @just header "Installing UniFFI Dependencies"
    @# Check if Node.js is installed
    @if ! command -v node > /dev/null; then \
        printf "{{error}}Error: Node.js is not installed. Please install Node.js first.{{reset}}\n"; \
        printf "{{info}}Visit: https://nodejs.org/ or use a package manager like brew, apt, etc.{{reset}}\n"; \
        exit 1; \
    else \
        printf "{{success}}✓ Node.js found: $(node --version){{reset}}\n"; \
    fi
    @# Check if npm is installed
    @if ! command -v npm > /dev/null; then \
        printf "{{error}}Error: npm is not installed. Please install npm first.{{reset}}\n"; \
        exit 1; \
    else \
        printf "{{success}}✓ npm found: $(npm --version){{reset}}\n"; \
    fi
    @# Install uniffi-bindgen-react-native globally if not already installed
    @if ! npm list -g uniffi-bindgen-react-native > /dev/null 2>&1; then \
        printf "{{info}}Installing uniffi-bindgen-react-native globally...{{reset}}\n" && \
        npm install -g uniffi-bindgen-react-native; \
    else \
        printf "{{success}}✓ uniffi-bindgen-react-native already installed globally{{reset}}\n"; \
    fi

# Setup complete development environment
setup: install-tools install-rust install-uniffi-deps
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

# Check for unused dependencies
udeps:
    @just header "Checking for unused dependencies"
    cargo udeps --workspace --all-targets

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

# Build the mdBook in docs/
mdbook-build:
    @just header "Building mdBook (docs/)"
    mdbook build docs

# Serve the mdBook locally with live reload
mdbook-serve:
    @just header "Serving mdBook at http://localhost:3000"
    mdbook serve docs --open --hostname 127.0.0.1 --port 3000

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
    just run-single-check "Unused dependencies" "cargo udeps --workspace --all-targets" || ERROR=1; \
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

# ensure wasm-bindgen-cli is installed
ensure-wasm-bindgen-cli:
    @if ! command -v wasm-bindgen > /dev/null || ! wasm-bindgen --version | grep -q "0.2.104"; then \
        printf "{{info}}Installing wasm-bindgen-cli 0.2.104...{{reset}}\n" && \
        cargo install wasm-bindgen-cli --version 0.2.104; \
    else \
        printf "{{success}}✓ wasm-bindgen-cli 0.2.104 already installed{{reset}}\n"; \
    fi

# installs wasm-opt via cargo if missing
install-wasm-opt:
    @if command -v wasm-opt >/dev/null 2>&1; then \
      printf "{{success}}✓ wasm-opt already installed{reset}}\n"; \
    else \
      cargo install wasm-opt --locked; \
      printf "{{success}}✓ Installed wasm-opt{reset}}\n"; \
    fi

# fails if wasm-opt is missing
ensure-wasm-opt:
    @if command -v wasm-opt >/dev/null 2>&1; then \
      printf "{{success}}✓ wasm-opt is installed{reset}}\n"; \
    else \
      printf "{{error}}wasm-opt not found on PATH{{reset}}\n"; \
      exit 1; \
    fi

gen-ts-bindings-debug:
    @just ensure-wasm-bindgen-cli # ensure wasm-bindgen-cli is installed
    @just header "Generating TypeScript bindings"
    cd mfkdf2-web && npm i && npm run ubrn:web
    @echo "Updating index.web.ts implementation"
    @cp mfkdf2-web/src/index.ts mfkdf2-web/src/index.web.ts

# Generate the TypeScript bindings
gen-ts-bindings:
    @just ensure-wasm-bindgen-cli # ensure wasm-bindgen-cli is installed
    @just header "Generating TypeScript bindings"
    cd mfkdf2-web && npm i && npm run ubrn:web:release
    @just ensure-wasm-opt # ensure wasm-opt is installed
    @just header "Optimizing WASM module"
    cd mfkdf2-web && npm run wasm:opt
    @echo "Updating index.web.ts implementation"
    @cp mfkdf2-web/src/index.ts mfkdf2-web/src/index.web.ts
    @just header "Point glue to optimized wasm"
    sed -i.bak 's/index_bg\.wasm/index_bg\.opt\.wasm/g' mfkdf2-web/src/index.web.ts && rm mfkdf2-web/src/index.web.ts.bak

gen-ts-bindings-differential:
    @just ensure-wasm-bindgen-cli # ensure wasm-bindgen-cli is installed
    @just header "Generating TypeScript bindings"
    cd mfkdf2-web && npm i && npm run ubrn:web:differential:release
    @echo "Updating index.web.ts implementation"
    @cp mfkdf2-web/src/index.ts mfkdf2-web/src/index.web.ts


# verify the TypeScript bindings
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

# test the TypeScript bindings
test-bindings:
    @just header "Testing TypeScript bindings"
    @just verify-bindings  # verify bindings is generated
    cd mfkdf2-web && npm test

# test the TypeScript bindings
test-bindings-differential:
    @just header "Testing TypeScript bindings (differential)"
    @just verify-bindings  # verify bindings is generated
    cd mfkdf2-web && npm run test:differential

# test the TypeScript bindings with HTML and JUnit reports
test-bindings-report:
    @just header "Testing TypeScript bindings (with reports)"
    @just verify-bindings  # verify bindings is generated
    cd mfkdf2-web && npm run test:report
    @printf "{{success}}HTML report:{{reset}} %s\n" "mfkdf2-web/test-results/mochawesome/index.html"
    @printf "{{success}}JUnit report:{{reset}} %s\n" "mfkdf2-web/test-results/junit/junit.xml"
