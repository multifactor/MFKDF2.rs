use std::{
  collections::HashMap,
  hint::black_box,
  time::{SystemTime, UNIX_EPOCH},
};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  derive,
  derive::factors::totp::TOTPDeriveOptions,
  otpauth::{HashAlgorithm, generate_hotp_code},
  setup::{
    self,
    factors::totp::{TOTPOptions, totp as setup_totp},
    key::MFKDF2Options,
  },
};

const SECRET20: [u8; 20] = *b"abcdefghijklmnopqrst";

fn bench_totp(c: &mut Criterion) {
  let mut group = c.benchmark_group("totp");

  // Get current time in seconds for TOTP
  let mut current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

  // Single setup - 1 TOTP
  group.bench_function("single_setup", |b| {
    b.iter(|| {
      let factor = black_box(
        setup_totp(TOTPOptions {
          id: Some("totp".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          time: Some(current_time),
          window: 3600, // 1 hour window
          ..Default::default()
        })
        .unwrap(),
      );
      let result = black_box(setup::key::key(&[factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 TOTP
  let single_setup_key = setup::key::key(
    &[setup_totp(TOTPOptions {
      id: Some("totp".to_string()),
      secret: Some(SECRET20.to_vec()),
      digits: 6,
      hash: HashAlgorithm::Sha1,
      time: Some(current_time),
      ..Default::default()
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

  group.bench_function("single_derive", |b| {
    b.iter(|| {
      // Create an oracle that provides the correct TOTP code for any time
      let mut oracle = HashMap::new();
      let totp_code = generate_hotp_code(&SECRET20, current_time / 30, &HashAlgorithm::Sha1, 6);
      oracle.insert(current_time / 30, totp_code);

      let factors_map = black_box(HashMap::from([(
        "totp".to_string(),
        derive::factors::totp(
          totp_code,
          Some(TOTPDeriveOptions { time: Some(current_time), oracle: Some(oracle) }),
        )
        .unwrap(),
      )]));
      let result = black_box(derive::key(&single_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

  // Multiple setup - 3 TOTPs with threshold 3 (all required)
  group.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key::key(
        &[
          setup_totp(TOTPOptions {
            id: Some("totp1".to_string()),
            secret: Some(SECRET20.to_vec()),
            digits: 6,
            hash: HashAlgorithm::Sha1,
            time: Some(current_time),
            window: 3600, // 1 hour window
            ..Default::default()
          })
          .unwrap(),
          setup_totp(TOTPOptions {
            id: Some("totp2".to_string()),
            secret: Some(vec![
              1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ]),
            digits: 6,
            hash: HashAlgorithm::Sha1,
            time: Some(current_time),
            window: 3600, // 1 hour window
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
            time: Some(current_time),
            window: 3600, // 1 hour window
            ..Default::default()
          })
          .unwrap(),
        ],
        options,
      ));
      result.unwrap()
    })
  });

  // Multiple derive - 3 TOTPs (all required)
  current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
  let multiple_setup_key_3 = setup::key::key(
    &[
      setup_totp(TOTPOptions {
        id: Some("totp1".to_string()),
        secret: Some(SECRET20.to_vec()),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(current_time),
        window: 3600, // 1 hour window
        ..Default::default()
      })
      .unwrap(),
      setup_totp(TOTPOptions {
        id: Some("totp2".to_string()),
        secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(current_time),
        window: 3600, // 1 hour window
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
        time: Some(current_time),
        window: 3600, // 1 hour window
        ..Default::default()
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
  group.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        (
          "totp1".to_string(),
          derive::factors::totp(
            generate_hotp_code(&SECRET20, current_time / 30, &HashAlgorithm::Sha1, 6),
            None,
          )
          .unwrap(),
        ),
        (
          "totp2".to_string(),
          derive::factors::totp(
            generate_hotp_code(
              &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
              current_time / 30,
              &HashAlgorithm::Sha1,
              6,
            ),
            None,
          )
          .unwrap(),
        ),
        (
          "totp3".to_string(),
          derive::factors::totp(
            generate_hotp_code(
              &[21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40],
              current_time / 30,
              &HashAlgorithm::Sha1,
              6,
            ),
            None,
          )
          .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(&multiple_setup_key_3.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 TOTPs
  current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
  let threshold_setup_key = setup::key::key(
    &[
      setup_totp(TOTPOptions {
        id: Some("totp1".to_string()),
        secret: Some(SECRET20.to_vec()),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(current_time),
        window: 3600, // 1 hour window
        ..Default::default()
      })
      .unwrap(),
      setup_totp(TOTPOptions {
        id: Some("totp2".to_string()),
        secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
        digits: 6,
        hash: HashAlgorithm::Sha1,
        time: Some(current_time),
        window: 3600, // 1 hour window
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
        time: Some(current_time),
        window: 3600, // 1 hour window
        ..Default::default()
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
  group.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        (
          "totp1".to_string(),
          derive::factors::totp(
            generate_hotp_code(&SECRET20, current_time / 30, &HashAlgorithm::Sha1, 6),
            None,
          )
          .unwrap(),
        ),
        (
          "totp2".to_string(),
          derive::factors::totp(
            generate_hotp_code(
              &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
              current_time / 30,
              &HashAlgorithm::Sha1,
              6,
            ),
            None,
          )
          .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(&threshold_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(totp_bench, bench_totp);
criterion_main!(totp_bench);
