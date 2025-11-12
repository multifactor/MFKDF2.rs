use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  derive,
  otpauth::HashAlgorithm,
  setup::{
    self,
    factors::totp::{TOTPOptions, totp as setup_totp},
    key::MFKDF2Options,
  },
};

const SECRET20: [u8; 20] = *b"abcdefghijklmnopqrst";

fn bench_totp(c: &mut Criterion) {
  // Single setup - 1 TOTP
  c.bench_function("single_setup", |b| {
    b.iter(|| {
      let factor = black_box(
        setup_totp(TOTPOptions {
          id: Some("totp".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          time: Some(1),
          ..Default::default()
        })
        .unwrap(),
      );
      let result = black_box(setup::key::key(vec![factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 TOTP
  let single_setup_key = setup::key::key(
    vec![
      setup_totp(TOTPOptions {
        id: Some("totp".to_string()),
        secret: Some(SECRET20.to_vec()),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(1),
        ..Default::default()
      })
      .unwrap(),
    ],
    MFKDF2Options::default(),
  )
  .unwrap();

  c.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map =
        black_box(HashMap::from([("totp".to_string(), derive::factors::totp(1, None).unwrap())]));
      let result =
        black_box(derive::key(single_setup_key.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 TOTPs with threshold 3 (all required)
  c.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let factors = black_box(vec![
        setup_totp(TOTPOptions {
          id: Some("totp1".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          time: Some(1),
          ..Default::default()
        })
        .unwrap(),
        setup_totp(TOTPOptions {
          id: Some("totp2".to_string()),
          secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          time: Some(1),
          ..Default::default()
        })
        .unwrap(),
        setup_totp(TOTPOptions {
          id: Some("totp3".to_string()),
          secret: Some(vec![
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
          ]),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          time: Some(1),
          ..Default::default()
        })
        .unwrap(),
      ]);
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key::key(factors, options));
      result.unwrap()
    })
  });

  // Multiple derive - 3 TOTPs (all required)
  let multiple_setup_key_3 = setup::key::key(
    vec![
      setup_totp(TOTPOptions {
        id: Some("totp1".to_string()),
        secret: Some(SECRET20.to_vec()),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(1),
        ..Default::default()
      })
      .unwrap(),
      setup_totp(TOTPOptions {
        id: Some("totp2".to_string()),
        secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(1),
        ..Default::default()
      })
      .unwrap(),
      setup_totp(TOTPOptions {
        id: Some("totp3".to_string()),
        secret: Some(vec![
          21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(1),
        ..Default::default()
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  c.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("totp1".to_string(), derive::factors::totp(1, None).unwrap()),
        ("totp2".to_string(), derive::factors::totp(1, None).unwrap()),
        ("totp3".to_string(), derive::factors::totp(1, None).unwrap()),
      ]));
      let result =
        black_box(derive::key(multiple_setup_key_3.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 TOTPs
  let threshold_setup_key = setup::key::key(
    vec![
      setup_totp(TOTPOptions {
        id: Some("totp1".to_string()),
        secret: Some(SECRET20.to_vec()),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(1),
        ..Default::default()
      })
      .unwrap(),
      setup_totp(TOTPOptions {
        id: Some("totp2".to_string()),
        secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(1),
        ..Default::default()
      })
      .unwrap(),
      setup_totp(TOTPOptions {
        id: Some("totp3".to_string()),
        secret: Some(vec![
          21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(1),
        ..Default::default()
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  c.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("totp1".to_string(), derive::factors::totp(1, None).unwrap()),
        ("totp2".to_string(), derive::factors::totp(1, None).unwrap()),
      ]));
      let result =
        black_box(derive::key(threshold_setup_key.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(totp_bench, bench_totp);
criterion_main!(totp_bench);
