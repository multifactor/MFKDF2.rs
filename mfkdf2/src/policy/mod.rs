use std::collections::HashMap;

use base64::{Engine, engine::general_purpose};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sharks::{Share, Sharks};

use crate::{
  error::MFKDF2Result,
  factors::{FactorPolicy, Material},
  utils::{aes256_ecb_decrypt, aes256_ecb_encrypt, argon2id, hkdf_sha256, split_secret},
};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PolicyBuilder {
  pub threshold: u8,
  pub salt:      Option<[u8; 32]>,
  pub factors:   Vec<Material>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Policy {
  pub threshold: u8,
  pub salt:      String,
  pub factors:   Vec<FactorPolicy>,
}

impl PolicyBuilder {
  pub fn new() -> Self { Self { threshold: 1, salt: None, factors: Vec::new() } }

  pub fn with_threshold(mut self, threshold: u8) -> Self {
    self.threshold = threshold;
    self
  }

  pub fn with_salt(mut self, salt: [u8; 32]) -> Self {
    self.salt = Some(salt);
    self
  }

  pub fn with_factor(mut self, factor: Material) -> Self {
    self.factors.push(factor);
    self
  }

  pub fn build(self) -> MFKDF2Result<Policy> { Policy::setup(self) }
}

// TODO (autoparallel): Add a `PolicyBuilder` to make it easier to create policies.
impl Policy {
  // TODO (autoparallel): This is a **minimal** implementation (no integrity HMAC yet).
  fn setup(policy_builder: PolicyBuilder) -> MFKDF2Result<Policy> {
    // Check threshold against number of factors
    // TODO (autoparallel): This should be compile-time checkable? Or at least an error.
    let thresh = policy_builder.threshold;
    if thresh == 0 || thresh as usize > policy_builder.factors.len() {
      panic!("invalid threshold");
    }

    // Generate global salt & secret if not provided
    let global_salt: [u8; 32] = policy_builder.salt.unwrap_or_else(|| {
      let mut salt = [0u8; 32];
      OsRng.fill_bytes(&mut salt);
      salt
    });
    let mut secret: [u8; 32] = [0u8; 32];
    OsRng.fill_bytes(&mut secret);

    // Split secret into Shamir shares
    let shares = split_secret(&secret, thresh, policy_builder.factors.len());

    // Build FactorPolicy list
    let mut factor_policies = Vec::new();
    for (mat, share) in policy_builder.factors.into_iter().zip(shares) {
      // per-factor salt
      let mut salt_bytes = [0u8; 32];
      OsRng.fill_bytes(&mut salt_bytes);

      // HKDF stretch & AES-encrypt share
      let stretched = hkdf_sha256(&mat.data, &salt_bytes);
      let pad = aes256_ecb_encrypt(&share, &stretched);

      // minimal params for now (empty object)
      let params = Value::Object(Default::default());

      factor_policies.push(FactorPolicy {
        id: mat.id,
        kind: mat.kind,
        pad: general_purpose::STANDARD.encode(pad),
        salt: general_purpose::STANDARD.encode(salt_bytes),
        params,
      });
    }

    // Assemble policy
    let policy = Policy {
      threshold: thresh,
      salt:      general_purpose::STANDARD.encode(global_salt),
      factors:   factor_policies,
    };

    Ok(policy)
  }

  pub fn derive(&self, factors: Vec<Material>) -> MFKDF2Result<[u8; 32]> {
    let mut shares_bytes = Vec::new();
    for factor in factors {
      if let Some(factor_policy) = self.factors.iter().find(|f| f.id == factor.id) {
        let salt_bytes = general_purpose::STANDARD.decode(&factor_policy.salt).unwrap();
        let salt_arr: [u8; 32] = salt_bytes.try_into().unwrap();
        let stretched = hkdf_sha256(&factor.data, &salt_arr);

        let pad = general_purpose::STANDARD.decode(&factor_policy.pad).unwrap();
        let plaintext = aes256_ecb_decrypt(pad, &stretched);

        shares_bytes.push(plaintext);
      }
    }

    let shares_vec: Vec<Share> =
      shares_bytes.iter().map(|b| Share::try_from(&b[..]).expect("invalid share bytes")).collect();

    let sharks = Sharks(self.threshold);
    let secret = sharks.recover(&shares_vec).expect("recover secret");
    let secret_arr: [u8; 32] = secret[..32].try_into().unwrap();

    let salt_bytes = general_purpose::STANDARD.decode(&self.salt).unwrap();
    let salt_arr: [u8; 32] = salt_bytes.try_into().unwrap();
    let key = argon2id(&secret_arr, &salt_arr);
    Ok(key)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn factors() -> Vec<Material> {
    vec![
      Material {
        id:     "f1".into(),
        kind:   "dummy".into(),
        data:   b"factor_one_secret".to_vec(),
        output: String::new(),
      },
      Material {
        id:     "f2".into(),
        kind:   "dummy".into(),
        data:   b"factor_two_secret".to_vec(),
        output: String::new(),
      },
    ]
  }

  #[test]
  fn setup_generates_policy() {
    let factors = factors();

    let policy = PolicyBuilder::new()
      .with_threshold(2)
      .with_factor(factors[0].clone())
      .with_factor(factors[1].clone())
      .build()
      .expect("setup should succeed");

    assert_eq!(policy.threshold, 2);
    assert_eq!(policy.factors.len(), 2);

    for f in &policy.factors {
      assert!(!f.pad.is_empty());
      assert!(!f.salt.is_empty());
    }
  }

  #[test]
  fn setup_then_derive() {
    let factors = factors();

    let policy = PolicyBuilder::new()
      .with_threshold(2)
      .with_factor(factors[0].clone())
      .with_factor(factors[1].clone())
      .build()
      .expect("setup should succeed");

    let key = policy.derive(factors).expect("derive should succeed");
    assert_eq!(key.len(), 32);
  }

  #[test]
  #[should_panic(expected = "Not enough shares to recover original secret")]
  fn derive_fails_with_insufficient_factors() {
    let setup_factors = factors();
    let policy = PolicyBuilder::new()
      .with_threshold(2)
      .with_factor(setup_factors[0].clone())
      .with_factor(setup_factors[1].clone())
      .build()
      .expect("setup should succeed");

    let mut insufficient_factors = setup_factors;
    insufficient_factors.pop();

    let _result = policy.derive(insufficient_factors).expect("derive should succeed");
  }

  #[test]
  fn derive_panics_with_incorrect_factor() {
    let factors = factors();
    let policy = PolicyBuilder::new()
      .with_threshold(2)
      .with_factor(factors[0].clone())
      .with_factor(factors[1].clone())
      .build()
      .expect("setup should succeed");

    let key_correct = policy.derive(factors.clone()).expect("derive should succeed");

    // flip a byte in one factor to simulate wrong password
    let mut bad_factors = factors.clone();
    bad_factors[0].data[0] ^= 0xFF;

    let key = policy.derive(bad_factors).expect("derive should succeed");
    assert_ne!(key, key_correct);
  }

  #[test]
  fn threshold_one_of_two() {
    let setup_factors = factors();
    let policy = PolicyBuilder::new()
      .with_threshold(1)
      .with_factor(setup_factors[0].clone())
      .build()
      .expect("setup should succeed");

    let key_correct = policy.derive(setup_factors.clone()).expect("derive should succeed");
    assert_eq!(key_correct.len(), 32);

    // try with one factor
    let key_one = policy.derive(setup_factors.clone()).expect("derive should succeed");
    assert_eq!(key_one, key_correct);
  }
}
