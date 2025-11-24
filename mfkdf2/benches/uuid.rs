use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  derive,
  setup::{
    self,
    factors::uuid::{UUIDOptions, uuid as setup_uuid},
    key::MFKDF2Options,
  },
};
use uuid::Uuid;

fn bench_uuid(c: &mut Criterion) {
  let mut group = c.benchmark_group("uuid");
  // Single setup - 1 UUID
  group.bench_function("single_setup", |b| {
    b.iter(|| {
      let factor = black_box(
        setup_uuid(UUIDOptions {
          id:   Some("uuid".to_string()),
          uuid: Some(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
        })
        .unwrap(),
      );
      let result = black_box(setup::key::key(&[factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 UUID
  let single_setup_key = setup::key::key(
    &[setup_uuid(UUIDOptions {
      id:   Some("uuid".to_string()),
      uuid: Some(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  group.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([(
        "uuid".to_string(),
        derive::factors::uuid(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap())
          .unwrap(),
      )]));
      let result = black_box(derive::key(&single_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 UUIDs with threshold 3 (all required)
  group.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key::key(
        &[
          setup_uuid(UUIDOptions {
            id:   Some("uuid1".to_string()),
            uuid: Some(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
          })
          .unwrap(),
          setup_uuid(UUIDOptions {
            id:   Some("uuid2".to_string()),
            uuid: Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()),
          })
          .unwrap(),
          setup_uuid(UUIDOptions {
            id:   Some("uuid3".to_string()),
            uuid: Some(Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap()),
          })
          .unwrap(),
        ],
        options,
      ));
      result.unwrap()
    })
  });

  // Multiple derive - 3 UUIDs (all required)
  let multiple_setup_key_3 = setup::key::key(
    &[
      setup_uuid(UUIDOptions {
        id:   Some("uuid1".to_string()),
        uuid: Some(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
      })
      .unwrap(),
      setup_uuid(UUIDOptions {
        id:   Some("uuid2".to_string()),
        uuid: Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()),
      })
      .unwrap(),
      setup_uuid(UUIDOptions {
        id:   Some("uuid3".to_string()),
        uuid: Some(Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap()),
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  group.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        (
          "uuid1".to_string(),
          derive::factors::uuid(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap())
            .unwrap(),
        ),
        (
          "uuid2".to_string(),
          derive::factors::uuid(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap())
            .unwrap(),
        ),
        (
          "uuid3".to_string(),
          derive::factors::uuid(Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap())
            .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(&multiple_setup_key_3.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 UUIDs
  let threshold_setup_key = setup::key::key(
    &[
      setup_uuid(UUIDOptions {
        id:   Some("uuid1".to_string()),
        uuid: Some(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
      })
      .unwrap(),
      setup_uuid(UUIDOptions {
        id:   Some("uuid2".to_string()),
        uuid: Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()),
      })
      .unwrap(),
      setup_uuid(UUIDOptions {
        id:   Some("uuid3".to_string()),
        uuid: Some(Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap()),
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  group.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        (
          "uuid1".to_string(),
          derive::factors::uuid(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap())
            .unwrap(),
        ),
        (
          "uuid2".to_string(),
          derive::factors::uuid(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap())
            .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(&threshold_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(uuid_bench, bench_uuid);
criterion_main!(uuid_bench);
