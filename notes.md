# Notes

## Uniffi

For other bindings, we can run:
```bash
cargo run --bin uniffi-bindgen generate --library target/debug/libmfkdf2.dylib --language python --out-dir out 
```

For TS bindings, we need to run the following command:

```bash
uniffi-bindgen-react-native generate wasm bindings --library --ts-dir out/ts --cpp-dir out/cpp target/debug/libmfkdf2.dylib
```