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

## Run Uniffi bindings
1. Make sure `yarn` is installed.
   1. TODO: move to npm.
2. `cd out/ts` and run `yarn`
3. generate bindings using `yarn ubrn:web`
4. run test using `yarn test`