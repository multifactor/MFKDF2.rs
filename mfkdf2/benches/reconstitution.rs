use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::setup::{
  self,
  factors::password::{PasswordOptions, password as setup_password},
  key::MFKDF2Options,
};

fn bench_reconstitution(c: &mut Criterion) {
  let mut group = c.benchmark_group("reconstitution");

  // Create initial setup with 3 factors, threshold 3

  let mut base_setup_key = setup::key(
    &[
      setup_password("password1", PasswordOptions { id: Some("password1".to_string()) }).unwrap(),
      setup_password("password2", PasswordOptions { id: Some("password2".to_string()) }).unwrap(),
      setup_password("password3", PasswordOptions { id: Some("password3".to_string()) }).unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), integrity: Some(false), ..Default::default() },
  )
  .unwrap();

  // Benchmark threshold change (3 -> 2)
  group.bench_function("set_threshold_3_to_2", |b| {
    b.iter(|| {
      let mut key_clone = base_setup_key.clone();
      let result = black_box(key_clone.set_threshold(2));
      result.unwrap()
    })
  });

  // Benchmark adding 2 factors
  let factors_to_add = vec![
    setup_password("password4", PasswordOptions { id: Some("password4".to_string()) }).unwrap(),
    setup_password("password5", PasswordOptions { id: Some("password5".to_string()) }).unwrap(),
  ];

  group.bench_function("add_2_factors", |b| {
    b.iter(|| {
      let mut key_clone = base_setup_key.clone();
      let result = black_box(key_clone.add_factors(&factors_to_add));
      result.unwrap()
    })
  });

  // First add the factors to the base key so we can test removal
  base_setup_key.add_factors(&factors_to_add).unwrap();

  // Benchmark removing 2 factors
  group.bench_function("remove_2_factors", |b| {
    b.iter(|| {
      let mut key_clone = base_setup_key.clone();
      let result = black_box(key_clone.remove_factors(&["password4", "password5"]));
      result.unwrap()
    })
  });
}

criterion_group!(reconstitution_bench, bench_reconstitution);
criterion_main!(reconstitution_bench);
