# switch to nightly rust
rustup default nightly

# install just
cargo install just
cargo install uniffi --features="cli" # this may have changed since the documentation attemps `cargo install uniffi-bindgen` and that no longer works

# dependencies
just install-wasm-opt # not done by setup
just setup
# just install-tools # done by above
# just install-rust # done by above
# just install-uniffi-deps # done by above
just ensure-wasm-bindgen-cli
