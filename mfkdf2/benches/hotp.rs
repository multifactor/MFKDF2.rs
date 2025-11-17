use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  derive,
  otpauth::HashAlgorithm,
  setup::{
    self,
    factors::hotp::{HOTPOptions, hotp as setup_hotp},
    key::MFKDF2Options,
  },
};

const SECRET20: [u8; 20] = *b"abcdefghijklmnopqrst";

fn bench_hotp(c: &mut Criterion) {
  let mut group = c.benchmark_group("hotp");
  // Single setup - 1 HOTP
  group.bench_function("single_setup", |b| {
    b.iter(|| {
      let factor = black_box(
        setup_hotp(HOTPOptions {
          id: Some("hotp".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          ..Default::default()
        })
        .unwrap(),
      );
      let result = black_box(setup::key::key(&[factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 HOTP
  let single_setup_key = setup::key::key(
    &[setup_hotp(HOTPOptions {
      id: Some("hotp".to_string()),
      secret: Some(SECRET20.to_vec()),
      digits: 6,
      hash: HashAlgorithm::Sha1,
      ..Default::default()
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  group.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map =
        black_box(HashMap::from([("hotp".to_string(), derive::factors::hotp(0).unwrap())]));
      let result =
        black_box(derive::key(single_setup_key.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 HOTPs with threshold 3 (all required)
  group.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let factors = black_box(vec![
        setup_hotp(HOTPOptions {
          id: Some("hotp1".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          ..Default::default()
        })
        .unwrap(),
        setup_hotp(HOTPOptions {
          id: Some("hotp2".to_string()),
          secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          ..Default::default()
        })
        .unwrap(),
        setup_hotp(HOTPOptions {
          id: Some("hotp3".to_string()),
          secret: Some(vec![
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
          ]),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          ..Default::default()
        })
        .unwrap(),
      ]);
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key::key(&factors, options));
      result.unwrap()
    })
  });

  // Multiple derive - 3 HOTPs (all required)
  let multiple_setup_key_3 = setup::key::key(
    &[
      setup_hotp(HOTPOptions {
        id: Some("hotp1".to_string()),
        secret: Some(SECRET20.to_vec()),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        ..Default::default()
      })
      .unwrap(),
      setup_hotp(HOTPOptions {
        id: Some("hotp2".to_string()),
        secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        ..Default::default()
      })
      .unwrap(),
      setup_hotp(HOTPOptions {
        id: Some("hotp3".to_string()),
        secret: Some(vec![
          21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        ..Default::default()
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  group.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("hotp1".to_string(), derive::factors::hotp(0).unwrap()),
        ("hotp2".to_string(), derive::factors::hotp(0).unwrap()),
        ("hotp3".to_string(), derive::factors::hotp(0).unwrap()),
      ]));
      let result =
        black_box(derive::key(multiple_setup_key_3.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 HOTPs
  let threshold_setup_key = setup::key::key(
    &[
      setup_hotp(HOTPOptions {
        id: Some("hotp1".to_string()),
        secret: Some(SECRET20.to_vec()),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        ..Default::default()
      })
      .unwrap(),
      setup_hotp(HOTPOptions {
        id: Some("hotp2".to_string()),
        secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        ..Default::default()
      })
      .unwrap(),
      setup_hotp(HOTPOptions {
        id: Some("hotp3".to_string()),
        secret: Some(vec![
          21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        ..Default::default()
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  group.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("hotp1".to_string(), derive::factors::hotp(0).unwrap()),
        ("hotp2".to_string(), derive::factors::hotp(0).unwrap()),
      ]));
      let result =
        black_box(derive::key(threshold_setup_key.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(hotp_bench, bench_hotp);
criterion_main!(hotp_bench);
