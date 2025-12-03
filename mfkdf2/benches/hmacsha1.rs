use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  definitions::MFKDF2Options,
  derive,
  setup::{
    self,
    factors::hmacsha1::{HmacSha1Options, hmacsha1},
  },
};

const SECRET20: [u8; 20] = *b"abcdefghijklmnopqrst";

fn bench_hmacsha1(c: &mut Criterion) {
  let mut group = c.benchmark_group("hmacsha1");
  // Single setup - 1 HMACSHA1
  group.bench_function("single_setup", |b| {
    b.iter(|| {
      let factor = black_box(
        hmacsha1(HmacSha1Options {
          id:     Some("hmac".to_string()),
          secret: Some(SECRET20.to_vec()),
        })
        .unwrap(),
      );
      let result = black_box(setup::key(&[factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 HMACSHA1
  let single_setup_key = setup::key(
    &[hmacsha1(HmacSha1Options {
      id:     Some("hmac".to_string()),
      secret: Some(SECRET20.to_vec()),
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  group.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([(
        "hmac".to_string(),
        derive::factors::hmacsha1(SECRET20).unwrap(),
      )]));
      let result = black_box(derive::key(&single_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 HMACSHA1 with threshold 3 (all required)
  group.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let factors = black_box([
        hmacsha1(HmacSha1Options {
          id:     Some("hmac1".to_string()),
          secret: Some(SECRET20.to_vec()),
        })
        .unwrap(),
        hmacsha1(HmacSha1Options {
          id:     Some("hmac2".to_string()),
          secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
        })
        .unwrap(),
        hmacsha1(HmacSha1Options {
          id:     Some("hmac3".to_string()),
          secret: Some(vec![
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
          ]),
        })
        .unwrap(),
      ]);
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key(&factors, options));
      result.unwrap()
    })
  });

  // Multiple derive - 3 HMACSHA1 (all required)
  let multiple_setup_key_3 = setup::key(
    &[
      hmacsha1(HmacSha1Options {
        id:     Some("hmac1".to_string()),
        secret: Some(SECRET20.to_vec()),
      })
      .unwrap(),
      hmacsha1(HmacSha1Options {
        id:     Some("hmac2".to_string()),
        secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
      })
      .unwrap(),
      hmacsha1(HmacSha1Options {
        id:     Some("hmac3".to_string()),
        secret: Some(vec![
          21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ]),
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  group.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("hmac1".to_string(), derive::factors::hmacsha1(SECRET20).unwrap()),
        (
          "hmac2".to_string(),
          derive::factors::hmacsha1([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
          ])
          .unwrap(),
        ),
        (
          "hmac3".to_string(),
          derive::factors::hmacsha1([
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
          ])
          .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(&multiple_setup_key_3.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 HMACSHA1
  let threshold_setup_key = setup::key(
    &[
      hmacsha1(HmacSha1Options {
        id:     Some("hmac1".to_string()),
        secret: Some(SECRET20.to_vec()),
      })
      .unwrap(),
      hmacsha1(HmacSha1Options {
        id:     Some("hmac2".to_string()),
        secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
      })
      .unwrap(),
      hmacsha1(HmacSha1Options {
        id:     Some("hmac3".to_string()),
        secret: Some(vec![
          21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ]),
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  group.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("hmac1".to_string(), derive::factors::hmacsha1(SECRET20).unwrap()),
        (
          "hmac2".to_string(),
          derive::factors::hmacsha1([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
          ])
          .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(&threshold_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(hmacsha1_bench, bench_hmacsha1);
criterion_main!(hmacsha1_bench);
