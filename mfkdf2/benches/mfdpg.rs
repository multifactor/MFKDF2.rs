use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  definitions::MFKDF2Options,
  derive,
  setup::{
    self,
    factors::password::{PasswordOptions, password as setup_password},
  },
};

fn bench_mfdpg(c: &mut Criterion) {
  let mut group = c.benchmark_group("mfdpg");

  // Setup a derived key for password derivation benchmarks
  let setup_key = setup::key(
    &[setup_password("password1", PasswordOptions { id: Some("password".to_string()) }).unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  let derived_key = derive::key(
    &setup_key.policy,
    HashMap::from([("password".to_string(), derive::factors::password("password1").unwrap())]),
    false,
    false,
  )
  .unwrap();

  // Simple regex pattern: alphanumeric, fixed length
  group.bench_function("derive_password_simple", |b| {
    b.iter(|| {
      black_box(
        derived_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z0-9]{8}").unwrap(),
      );
    })
  });

  // Medium complexity: alphabetic, variable length
  group.bench_function("derive_password_medium", |b| {
    b.iter(|| {
      black_box(
        derived_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}").unwrap(),
      );
    })
  });

  // Complex regex pattern: mixed alphanumeric with specific structure
  group.bench_function("derive_password_complex", |b| {
    b.iter(|| {
      black_box(
        derived_key
          .derive_password(
            Some("example.com"),
            Some(b"salt"),
            "([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*",
          )
          .unwrap(),
      );
    })
  });

  // Very simple pattern: just digits
  group.bench_function("derive_password_digits_only", |b| {
    b.iter(|| {
      black_box(
        derived_key.derive_password(Some("example.com"), Some(b"salt"), "[0-9]{6}").unwrap(),
      );
    })
  });

  // Long pattern: longer password
  group.bench_function("derive_password_long", |b| {
    b.iter(|| {
      black_box(
        derived_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z0-9]{16}").unwrap(),
      );
    })
  });
}

criterion_group!(mfdpg_bench, bench_mfdpg);
criterion_main!(mfdpg_bench);
