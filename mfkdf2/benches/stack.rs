use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  definitions::{MFKDF2Factor, MFKDF2Options},
  derive,
  setup::{
    self,
    factors::{
      password::{PasswordOptions, password as setup_password},
      stack::{StackOptions, stack as setup_stack},
    },
  },
};

// Helper function to create a stack factor with two passwords
fn create_stack_factor(
  stack_id: &str,
  pw1_id: &str,
  pw1_value: &str,
  pw2_id: &str,
  pw2_value: &str,
) -> Result<MFKDF2Factor, mfkdf2::error::MFKDF2Error> {
  setup_stack(
    vec![
      setup_password(pw1_value.to_string(), PasswordOptions { id: Some(pw1_id.to_string()) })
        .unwrap(),
      setup_password(pw2_value.to_string(), PasswordOptions { id: Some(pw2_id.to_string()) })
        .unwrap(),
    ],
    StackOptions { id: Some(stack_id.to_string()), ..Default::default() },
  )
}

// Helper function to create a derive stack factor map
fn create_stack_derive_map(
  stack_id: &str,
  pw1_id: &str,
  pw1_value: &str,
  pw2_id: &str,
  pw2_value: &str,
) -> HashMap<String, MFKDF2Factor> {
  HashMap::from([(
    stack_id.to_string(),
    derive::factors::stack(HashMap::from([
      (pw1_id.to_string(), derive::factors::password(pw1_value).unwrap()),
      (pw2_id.to_string(), derive::factors::password(pw2_value).unwrap()),
    ]))
    .unwrap(),
  )])
}

fn bench_setup_stack(c: &mut Criterion) {
  let mut group = c.benchmark_group("stack");
  // Single setup - 1 stack
  group.bench_function("single_setup", |b| {
    b.iter(|| {
      let factor = black_box(create_stack_factor("stack", "p1", "pw1", "p2", "pw2").unwrap());
      let result = black_box(setup::key(&[factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 stack
  let single_setup_key = setup::key(
    &[create_stack_factor("stack", "p1", "pw1", "p2", "pw2").unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  group.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map = black_box(create_stack_derive_map("stack", "p1", "pw1", "p2", "pw2"));
      let result = black_box(derive::key(&single_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 stacks with threshold 3 (all required)
  group.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key(
        &[
          create_stack_factor("s1", "s1p1", "s1p1", "s1p2", "s1p2").unwrap(),
          create_stack_factor("s2", "s2p1", "s2p1", "s2p2", "s2p2").unwrap(),
          create_stack_factor("s3", "s3p1", "s3p1", "s3p2", "s3p2").unwrap(),
        ],
        options,
      ));
      result.unwrap()
    })
  });

  // Multiple derive - 3 stacks (all required)
  let multiple_setup_key_3 = setup::key(
    &[
      create_stack_factor("s1", "s1p1", "s1p1", "s1p2", "s1p2").unwrap(),
      create_stack_factor("s2", "s2p1", "s2p1", "s2p2", "s2p2").unwrap(),
      create_stack_factor("s3", "s3p1", "s3p1", "s3p2", "s3p2").unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  group.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        (
          "s1".to_string(),
          derive::factors::stack(HashMap::from([
            ("s1p1".to_string(), derive::factors::password("s1p1").unwrap()),
            ("s1p2".to_string(), derive::factors::password("s1p2").unwrap()),
          ]))
          .unwrap(),
        ),
        (
          "s2".to_string(),
          derive::factors::stack(HashMap::from([
            ("s2p1".to_string(), derive::factors::password("s2p1").unwrap()),
            ("s2p2".to_string(), derive::factors::password("s2p2").unwrap()),
          ]))
          .unwrap(),
        ),
        (
          "s3".to_string(),
          derive::factors::stack(HashMap::from([
            ("s3p1".to_string(), derive::factors::password("s3p1").unwrap()),
            ("s3p2".to_string(), derive::factors::password("s3p2").unwrap()),
          ]))
          .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(&multiple_setup_key_3.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 stacks
  let threshold_setup_key = setup::key(
    &[
      create_stack_factor("s1", "s1p1", "s1p1", "s1p2", "s1p2").unwrap(),
      create_stack_factor("s2", "s2p1", "s2p1", "s2p2", "s2p2").unwrap(),
      create_stack_factor("s3", "s3p1", "s3p1", "s3p2", "s3p2").unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  group.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        (
          "s1".to_string(),
          derive::factors::stack(HashMap::from([
            ("s1p1".to_string(), derive::factors::password("s1p1").unwrap()),
            ("s1p2".to_string(), derive::factors::password("s1p2").unwrap()),
          ]))
          .unwrap(),
        ),
        (
          "s2".to_string(),
          derive::factors::stack(HashMap::from([
            ("s2p1".to_string(), derive::factors::password("s2p1").unwrap()),
            ("s2p2".to_string(), derive::factors::password("s2p2").unwrap()),
          ]))
          .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(&threshold_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(stack_bench, bench_setup_stack);
criterion_main!(stack_bench);
