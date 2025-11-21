use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  definitions::MFKDF2Options,
  derive,
  setup::{
    self,
    factors::passkey::{PasskeyOptions, passkey as setup_passkey},
  },
};

fn bench_setup_passkey(c: &mut Criterion) {
  let mut group = c.benchmark_group("passkey");
  // Single setup - 1 passkey
  group.bench_function("single_setup", |b| {
    b.iter(|| {
      let secret = [42u8; 32];
      let factor = black_box(setup_passkey(secret, PasskeyOptions::default()).unwrap());
      let result = black_box(setup::key(&[factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 passkey
  let secret = [42u8; 32];
  let single_setup_key = setup::key(
    &[setup_passkey(secret, PasskeyOptions { id: Some("passkey".to_string()) }).unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  group.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([(
        "passkey".to_string(),
        derive::factors::passkey(secret).unwrap(),
      )]));
      let result = black_box(derive::key(&single_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 passkeys with threshold 3 (all required)
  group.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key(
        &[
          setup_passkey([1u8; 32], PasskeyOptions { id: Some("passkey1".to_string()) }).unwrap(),
          setup_passkey([2u8; 32], PasskeyOptions { id: Some("passkey2".to_string()) }).unwrap(),
          setup_passkey([3u8; 32], PasskeyOptions { id: Some("passkey3".to_string()) }).unwrap(),
        ],
        options,
      ));
      result.unwrap()
    })
  });

  // Multiple derive - 3 passkeys (all required)
  let multiple_setup_key_3 = setup::key(
    &[
      setup_passkey([1u8; 32], PasskeyOptions { id: Some("passkey1".to_string()) }).unwrap(),
      setup_passkey([2u8; 32], PasskeyOptions { id: Some("passkey2".to_string()) }).unwrap(),
      setup_passkey([3u8; 32], PasskeyOptions { id: Some("passkey3".to_string()) }).unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  group.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("passkey1".to_string(), derive::factors::passkey([1u8; 32]).unwrap()),
        ("passkey2".to_string(), derive::factors::passkey([2u8; 32]).unwrap()),
        ("passkey3".to_string(), derive::factors::passkey([3u8; 32]).unwrap()),
      ]));
      let result = black_box(derive::key(&multiple_setup_key_3.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 passkeys
  let threshold_setup_key = setup::key(
    &[
      setup_passkey([1u8; 32], PasskeyOptions { id: Some("passkey1".to_string()) }).unwrap(),
      setup_passkey([2u8; 32], PasskeyOptions { id: Some("passkey2".to_string()) }).unwrap(),
      setup_passkey([3u8; 32], PasskeyOptions { id: Some("passkey3".to_string()) }).unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  group.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("passkey1".to_string(), derive::factors::passkey([1u8; 32]).unwrap()),
        ("passkey2".to_string(), derive::factors::passkey([2u8; 32]).unwrap()),
      ]));
      let result = black_box(derive::key(&threshold_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(passkey_bench, bench_setup_passkey);
criterion_main!(passkey_bench);
