use std::{collections::HashMap, hint::black_box};

use base64::Engine;
use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  derive,
  setup::{
    self,
    factors::ooba::{OobaOptions, ooba as setup_ooba},
    key::MFKDF2Options,
  },
};
use rsa::traits::PublicKeyParts;
use serde_json::json;

fn create_jwk(bits: usize) -> serde_json::Value {
  let private_key =
    rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).expect("failed to generate key");
  let public_key = rsa::RsaPublicKey::from(&private_key);
  let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
  let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
  json!({
      "key_ops": ["encrypt", "decrypt"],
      "ext": true,
      "alg": "RSA-OAEP-256",
      "kty": "RSA",
      "n": n,
      "e": e
  })
}

fn bench_ooba(c: &mut Criterion) {
  // Single setup - 1 OOBA
  c.bench_function("single_setup", |b| {
    b.iter(|| {
      let jwk = create_jwk(2048);
      let factor = black_box(
        setup_ooba(OobaOptions {
          id: Some("ooba".to_string()),
          key: Some(serde_json::from_value(jwk).unwrap()),
          params: Some(json!({"email": "user@example.com"})),
          ..Default::default()
        })
        .unwrap(),
      );
      let result = black_box(setup::key::key(vec![factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 OOBA
  let jwk = create_jwk(2048);
  let single_setup_key = setup::key::key(
    vec![
      setup_ooba(OobaOptions {
        id: Some("ooba".to_string()),
        key: Some(serde_json::from_value(jwk.clone()).unwrap()),
        params: Some(json!({"email": "user@example.com"})),
        ..Default::default()
      })
      .unwrap(),
    ],
    MFKDF2Options::default(),
  )
  .unwrap();

  c.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([(
        "ooba".to_string(),
        derive::factors::ooba("challenge_response".to_string()).unwrap(),
      )]));
      let result =
        black_box(derive::key(single_setup_key.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 OOBAs with threshold 3 (all required)
  c.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let jwk1 = create_jwk(2048);
      let jwk2 = create_jwk(2048);
      let jwk3 = create_jwk(2048);

      let factors = black_box(vec![
        setup_ooba(OobaOptions {
          id: Some("ooba1".to_string()),
          key: Some(serde_json::from_value(jwk1).unwrap()),
          params: Some(json!({"email": "user1@example.com"})),
          ..Default::default()
        })
        .unwrap(),
        setup_ooba(OobaOptions {
          id: Some("ooba2".to_string()),
          key: Some(serde_json::from_value(jwk2).unwrap()),
          params: Some(json!({"email": "user2@example.com"})),
          ..Default::default()
        })
        .unwrap(),
        setup_ooba(OobaOptions {
          id: Some("ooba3".to_string()),
          key: Some(serde_json::from_value(jwk3).unwrap()),
          params: Some(json!({"email": "user3@example.com"})),
          ..Default::default()
        })
        .unwrap(),
      ]);
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key::key(factors, options));
      result.unwrap()
    })
  });

  // Multiple derive - 3 OOBAs (all required)
  let jwk1 = create_jwk(2048);
  let jwk2 = create_jwk(2048);
  let jwk3 = create_jwk(2048);

  let multiple_setup_key_3 = setup::key::key(
    vec![
      setup_ooba(OobaOptions {
        id: Some("ooba1".to_string()),
        key: Some(serde_json::from_value(jwk1).unwrap()),
        params: Some(json!({"email": "user1@example.com"})),
        ..Default::default()
      })
      .unwrap(),
      setup_ooba(OobaOptions {
        id: Some("ooba2".to_string()),
        key: Some(serde_json::from_value(jwk2).unwrap()),
        params: Some(json!({"email": "user2@example.com"})),
        ..Default::default()
      })
      .unwrap(),
      setup_ooba(OobaOptions {
        id: Some("ooba3".to_string()),
        key: Some(serde_json::from_value(jwk3).unwrap()),
        params: Some(json!({"email": "user3@example.com"})),
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
        ("ooba1".to_string(), derive::factors::ooba("challenge_response1".to_string()).unwrap()),
        ("ooba2".to_string(), derive::factors::ooba("challenge_response2".to_string()).unwrap()),
        ("ooba3".to_string(), derive::factors::ooba("challenge_response3".to_string()).unwrap()),
      ]));
      let result =
        black_box(derive::key(multiple_setup_key_3.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 OOBAs
  let jwk1 = create_jwk(2048);
  let jwk2 = create_jwk(2048);
  let jwk3 = create_jwk(2048);

  let threshold_setup_key = setup::key::key(
    vec![
      setup_ooba(OobaOptions {
        id: Some("ooba1".to_string()),
        key: Some(serde_json::from_value(jwk1).unwrap()),
        params: Some(json!({"email": "user1@example.com"})),
        ..Default::default()
      })
      .unwrap(),
      setup_ooba(OobaOptions {
        id: Some("ooba2".to_string()),
        key: Some(serde_json::from_value(jwk2).unwrap()),
        params: Some(json!({"email": "user2@example.com"})),
        ..Default::default()
      })
      .unwrap(),
      setup_ooba(OobaOptions {
        id: Some("ooba3".to_string()),
        key: Some(serde_json::from_value(jwk3).unwrap()),
        params: Some(json!({"email": "user3@example.com"})),
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
        ("ooba1".to_string(), derive::factors::ooba("challenge_response1".to_string()).unwrap()),
        ("ooba2".to_string(), derive::factors::ooba("challenge_response2".to_string()).unwrap()),
      ]));
      let result =
        black_box(derive::key(threshold_setup_key.policy.clone(), factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(ooba_bench, bench_ooba);
criterion_main!(ooba_bench);
