use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  derive,
  setup::{
    self,
    factors::password::{PasswordOptions, password as setup_password},
    key::MFKDF2Options,
  },
};

fn bench_mfdpg(c: &mut Criterion) {
  let mut group = c.benchmark_group("mfdpg");

  // Setup a derived key for password derivation benchmarks
  let setup_key = setup::key::key(
    vec![
      setup_password("password1", PasswordOptions { id: Some("password".to_string()) }).unwrap(),
    ],
    MFKDF2Options::default(),
  )
  .unwrap();

  let derived_key = derive::key(
    setup_key.policy.clone(),
    HashMap::from([("password".to_string(), derive::factors::password("password1").unwrap())]),
    false,
    false,
  )
  .unwrap();

  // Simple regex pattern: alphanumeric, fixed length
  group.bench_function("derive_password_simple", |b| {
    b.iter(|| {
      let result = black_box(derived_key.derive_password(
        Some("example.com"),
        Some(b"salt"),
        "[a-zA-Z0-9]{8}",
      ));
      result
    })
  });

  // Medium complexity: alphabetic, variable length
  group.bench_function("derive_password_medium", |b| {
    b.iter(|| {
      let result = black_box(derived_key.derive_password(
        Some("example.com"),
        Some(b"salt"),
        "[a-zA-Z]{6,10}",
      ));
      result
    })
  });

  // Complex regex pattern: mixed alphanumeric with specific structure
  group.bench_function("derive_password_complex", |b| {
    b.iter(|| {
      let result = black_box(derived_key.derive_password(
        Some("example.com"),
        Some(b"salt"),
        "([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*",
      ));
      result
    })
  });

  // Very simple pattern: just digits
  group.bench_function("derive_password_digits_only", |b| {
    b.iter(|| {
      let result =
        black_box(derived_key.derive_password(Some("example.com"), Some(b"salt"), "[0-9]{6}"));
      result
    })
  });

  // Long pattern: longer password
  group.bench_function("derive_password_long", |b| {
    b.iter(|| {
      let result = black_box(derived_key.derive_password(
        Some("example.com"),
        Some(b"salt"),
        "[a-zA-Z0-9]{16}",
      ));
      result
    })
  });
}

criterion_group!(mfdpg_bench, bench_mfdpg);
criterion_main!(mfdpg_bench);
