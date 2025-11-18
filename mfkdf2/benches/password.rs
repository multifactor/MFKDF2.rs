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

fn bench_password(c: &mut Criterion) {
  let mut group = c.benchmark_group("password");
  // Single setup - 1 password
  group.bench_function("single_setup", |b| {
    b.iter(|| {
      let factor = black_box(setup_password("password1", PasswordOptions::default()).unwrap());
      let result = black_box(setup::key::key(&[factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 password
  let single_setup_key = setup::key::key(
    &[setup_password("password1", PasswordOptions { id: Some("pwd".to_string()) }).unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  group.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([(
        "pwd".to_string(),
        derive::factors::password("password1").unwrap(),
      )]));
      let result = black_box(derive::key(&single_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 passwords with threshold 3 (all required)
  group.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key::key(
        &[
          setup_password("password1", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap(),
          setup_password("password2", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap(),
          setup_password("password3", PasswordOptions { id: Some("pwd3".to_string()) }).unwrap(),
        ],
        options,
      ));
      result.unwrap()
    })
  });

  // Multiple derive - 3 passwords (all required)
  let multiple_setup_key_3 = setup::key::key(
    &[
      setup_password("password1", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap(),
      setup_password("password2", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap(),
      setup_password("password3", PasswordOptions { id: Some("pwd3".to_string()) }).unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  group.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("pwd1".to_string(), derive::factors::password("password1").unwrap()),
        ("pwd2".to_string(), derive::factors::password("password2").unwrap()),
        ("pwd3".to_string(), derive::factors::password("password3").unwrap()),
      ]));
      let result = black_box(derive::key(&multiple_setup_key_3.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 passwords
  let threshold_setup_key = setup::key::key(
    &[
      setup_password("password1", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap(),
      setup_password("password2", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap(),
      setup_password("password3", PasswordOptions { id: Some("pwd3".to_string()) }).unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  group.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("pwd1".to_string(), derive::factors::password("password1").unwrap()),
        ("pwd2".to_string(), derive::factors::password("password2").unwrap()),
      ]));
      let result = black_box(derive::key(&threshold_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(password_bench, bench_password);
criterion_main!(password_bench);
