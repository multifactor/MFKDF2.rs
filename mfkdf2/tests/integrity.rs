#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashMap;

use mfkdf2::{definitions::MFKDF2DerivedKey, policy::Policy};

use crate::common::{create_derive_factor, create_setup_factor};

fn make_policy(setup_factor_names: &[&str], threshold: u8, integrity: bool) -> MFKDF2DerivedKey {
  let setup_factors: Vec<_> = setup_factor_names.iter().copied().map(create_setup_factor).collect();

  let options = mfkdf2::setup::key::MFKDF2Options {
    threshold: Some(threshold),
    integrity: Some(integrity),
    ..Default::default()
  };

  mfkdf2::setup::key(&setup_factors, options).unwrap()
}

fn derive_once(
  policy: &Policy,
  factor_names: &[&str],
  verify_integrity: bool,
) -> mfkdf2::definitions::MFKDF2DerivedKey {
  // build derive map using the shared harness (needs policy for TOTP/HOTP codes)
  let derive_map: HashMap<_, _> =
    factor_names.iter().map(|name| create_derive_factor(name, policy)).collect();

  // derive
  mfkdf2::derive::key(policy, derive_map, verify_integrity, false).unwrap()
}

#[test]
fn integrity_disabled_allows_tamper() {
  // 4-of-4, integrity disabled; mix of factors to exercise the harness
  let setup_derived_key = make_policy(&["password", "hotp", "totp", "uuid"], 4, false);

  let mut policy = setup_derived_key.policy.clone();

  // Tamper factor id: change the password factor's id from "password_1" to "tampered"
  if let Some(f) = policy.factors.iter_mut().find(|f| f.id == "password_1") {
    f.id = "tampered".to_string();
  } else {
    panic!("password_1 factor not found in policy");
  }

  // Build derive map; override the id for the password entry to match the tampered id
  let mut derive_map: HashMap<String, mfkdf2::definitions::MFKDF2Factor> = HashMap::new();
  for name in ["password", "hotp", "totp", "uuid"] {
    let (mut id, factor) = create_derive_factor(name, &policy);
    if name == "password" {
      id = "tampered".to_string();
    }
    derive_map.insert(id, factor);
  }

  // With integrity verification OFF, derivation must still succeed
  let derived = mfkdf2::derive::key(&policy, derive_map, false, false).unwrap();
  // quick sanity: we can re-derive once more from the mutated policy
  let _ = mfkdf2::derive::key(&derived.policy, HashMap::new(), false, false); // empty map just ensures type compiles; not used
}

#[test]
fn integrity_enabled_clean_liveness() {
  // integrity enabled; clean policy should derive and remain stable across runs
  let setup_derived_key = make_policy(&["password", "hotp", "totp", "uuid"], 4, true);

  let policy = setup_derived_key.policy;

  let d1 = derive_once(&policy, &["password", "hotp", "totp", "uuid"], true);
  let d2 = derive_once(&d1.policy, &["password", "hotp", "totp", "uuid"], true);

  assert_eq!(d1.key, d2.key);
  assert_eq!(d1.secret, d2.secret);
}

#[test]
fn integrity_enabled_rejects_policy_id_tamper() {
  let setup_derived_key = make_policy(&["password", "uuid"], 2, true);

  let mut policy = setup_derived_key.policy;

  policy.id = "tampered".to_string();

  let derive_map: HashMap<_, _> =
    ["password", "uuid"].iter().map(|name| create_derive_factor(name, &policy)).collect();

  let res = mfkdf2::derive::key(&policy, derive_map, true, false);
  assert!(res.is_err(), "expected integrity verification to fail after policy.id tamper");
}

#[test]
fn integrity_enabled_rejects_threshold_tamper() {
  let setup_derived_key = make_policy(&["password", "question"], 2, true);

  let mut policy = setup_derived_key.policy;

  // Tamper threshold
  policy.threshold += 1;

  let derive_map: HashMap<_, _> =
    ["password", "question"].iter().map(|name| create_derive_factor(name, &policy)).collect();

  let res = mfkdf2::derive::key(&policy, derive_map, true, false);
  assert!(res.is_err(), "expected integrity verification to fail after threshold tamper");
}

#[test]
fn integrity_enabled_rejects_salt_tamper() {
  let setup_derived_key = make_policy(&["password", "totp"], 2, true);

  let mut policy = setup_derived_key.policy;

  // Tamper salt (base64)
  policy.salt = "Ny9+L9LQHOKh1x3Acqy7pMb9JaEIfNfxU/TsDON+Ht4=".to_string();

  let derive_map: HashMap<_, _> =
    ["password", "totp"].iter().map(|name| create_derive_factor(name, &policy)).collect();

  let res = mfkdf2::derive::key(&policy, derive_map, true, false);
  assert!(res.is_err(), "expected integrity verification to fail after salt tamper");
}

#[test]
fn integrity_enabled_rejects_factor_id_tamper() {
  let setup_derived_key = make_policy(&["password", "uuid"], 2, true);

  let mut policy = setup_derived_key.policy;

  // Tamper a factor id (password)
  if let Some(f) = policy.factors.iter_mut().find(|f| f.id == "password_1") {
    f.id = "tampered".to_string();
  } else {
    panic!("password_1 factor not found in policy");
  }

  // Build derive map supplying password under tampered id — integrity must still reject
  let mut derive_map: HashMap<String, mfkdf2::definitions::MFKDF2Factor> = HashMap::new();
  for name in ["password", "uuid"] {
    let (mut id, factor) = create_derive_factor(name, &policy);
    if name == "password" {
      id = "tampered".to_string();
    }
    derive_map.insert(id, factor);
  }

  let res = mfkdf2::derive::key(&policy, derive_map, true, false);
  assert!(res.is_err(), "expected integrity verification to fail after factor id tamper");
}

#[test]
fn integrity_enabled_rejects_derived_policy_tamper() {
  // Start clean with integrity=true
  let setup_derived_key = make_policy(&["password", "hotp", "totp", "uuid"], 4, true);

  let policy = setup_derived_key.policy;

  // First derive succeeds
  let derived = derive_once(&policy, &["password", "hotp", "uuid", "totp"], true);

  // Tamper the returned policy's first matching factor id (password)
  let mut tampered = derived.policy.clone();
  if let Some(f) = tampered.factors.iter_mut().find(|f| f.id == "password_1") {
    f.id = "tampered".to_string();
  } else {
    panic!("password_1 factor not found in derived policy");
  }

  // Supply factors; integrity ON must now reject
  let mut derive_map: HashMap<String, mfkdf2::definitions::MFKDF2Factor> = HashMap::new();
  for name in ["password", "hotp", "uuid", "totp"] {
    let (mut id, factor) = create_derive_factor(name, &tampered);
    if name == "password" {
      id = "tampered".to_string();
    }
    derive_map.insert(id, factor);
  }

  let res = mfkdf2::derive::key(&tampered, derive_map, true, false);
  assert!(res.is_err(), "expected integrity verification to fail after tampering derived policy");
}
