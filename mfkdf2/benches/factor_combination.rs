use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  derive,
  derive::factors::totp::TOTPDeriveOptions,
  otpauth::{HashAlgorithm, generate_hotp_code},
  setup::{
    self,
    factors::{
      hmacsha1::{HmacSha1Options, hmacsha1},
      hotp::{HOTPOptions, hotp},
      password::{PasswordOptions, password},
      totp::{TOTPOptions, totp},
      uuid::{UUIDOptions, uuid},
    },
    key::MFKDF2Options,
  },
};
use uuid::Uuid;

const SECRET20: [u8; 20] = *b"abcdefghijklmnopqrst";

fn bench_factor_combination_setup(c: &mut Criterion) {
  let mut group = c.benchmark_group("factor_combination");
  // Case A: 5-of-5 factors (password + hmacsha1 + hotp + totp + uuid)
  group.bench_function("setup_5_factors", |b| {
    b.iter(|| {
      let factors = black_box([
        password("password1", PasswordOptions::default()).unwrap(),
        hmacsha1(HmacSha1Options {
          id:     Some("hmacsha1".to_string()),
          secret: Some(SECRET20.to_vec()),
        })
        .unwrap(),
        hotp(HOTPOptions {
          id: Some("hotp".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          ..Default::default()
        })
        .unwrap(),
        totp(TOTPOptions {
          id: Some("totp".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          time: Some(1),
          ..Default::default()
        })
        .unwrap(),
        uuid(UUIDOptions {
          id:   Some("uuid".to_string()),
          uuid: Some(Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
        })
        .unwrap(),
      ]);
      let result = black_box(setup::key::key(&factors, MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Case B: 3-of-3 factors (password + hotp + totp)
  group.bench_function("setup_3_factors", |b| {
    b.iter(|| {
      let factors = black_box([
        password("password1", PasswordOptions::default()).unwrap(),
        hotp(HOTPOptions {
          id: Some("hotp".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          ..Default::default()
        })
        .unwrap(),
        totp(TOTPOptions {
          id: Some("totp".to_string()),
          secret: Some(SECRET20.to_vec()),
          digits: 6,
          hash: HashAlgorithm::Sha1,
          time: Some(1),
          ..Default::default()
        })
        .unwrap(),
      ]);
      let result = black_box(setup::key::key(&factors, MFKDF2Options::default()));
      result.unwrap()
    })
  });
}

fn bench_factor_combination_derive(c: &mut Criterion) {
  let mut group = c.benchmark_group("factor_combination");
  // Setup phase: password + hotp + totp with threshold 2
  let factor1 = password("password1", PasswordOptions { id: Some("pwd".to_string()) }).unwrap();
  let factor2 = hotp(HOTPOptions {
    id: Some("hotp".to_string()),
    secret: Some(SECRET20.to_vec()),
    digits: 6,
    hash: HashAlgorithm::Sha1,
    ..Default::default()
  })
  .unwrap();
  let factor3 = totp(TOTPOptions {
    id: Some("totp".to_string()),
    secret: Some(SECRET20.to_vec()),
    digits: 6,
    hash: HashAlgorithm::Sha1,
    time: Some(1),
    ..Default::default()
  })
  .unwrap();

  let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
  let setup_key = setup::key::key(&[factor1, factor2, factor3], options).unwrap();

  // Pre-compute HOTP code for derive
  let policy_hotp_factor = setup_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
  let hotp_params = &policy_hotp_factor.params;
  let counter = hotp_params["counter"].as_u64().unwrap();
  let hotp_code = generate_hotp_code(&SECRET20, counter, &HashAlgorithm::Sha1, 6);

  // Pre-compute TOTP code for derive
  let time = 1;
  let totp_counter = time / 30;
  let totp_code = generate_hotp_code(&SECRET20, totp_counter, &HashAlgorithm::Sha1, 6);

  // Benchmark derive with password + hotp (threshold 2 of 3)
  group.bench_function("derive_password_hotp", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("pwd".to_string(), derive::factors::password("password1").unwrap()),
        ("hotp".to_string(), derive::factors::hotp(hotp_code as u32).unwrap()),
      ]));
      let result = black_box(derive::key(setup_key.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });

  // Benchmark derive with password + totp (threshold 2 of 3)
  group.bench_function("derive_password_totp", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("pwd".to_string(), derive::factors::password("password1").unwrap()),
        (
          "totp".to_string(),
          derive::factors::totp(
            totp_code,
            Some(TOTPDeriveOptions { time: Some(time), oracle: None }),
          )
          .unwrap(),
        ),
      ]));
      let result = black_box(derive::key(setup_key.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(
  factor_combination,
  bench_factor_combination_setup,
  bench_factor_combination_derive
);
criterion_main!(factor_combination);
