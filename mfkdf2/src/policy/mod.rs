use std::collections::HashSet;

use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::{Factor, Material},
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
  pub factors:   Vec<Factor>,
  pub integrity: [u8; 32],
  // TODO (autoparallel): This is so we can track the real entropy of the policy.
  // pub entropy_real: u32,
  //
  // TODO (autoparallel): This is so we can track the theoretical entropy of the policy.
  // pub entropy_theoretical: u32,
}

impl Default for PolicyBuilder {
  fn default() -> Self { Self::new() }
}

impl PolicyBuilder {
  pub const fn new() -> Self { Self { threshold: 1, salt: None, factors: Vec::new() } }

  pub const fn with_threshold(mut self, threshold: u8) -> Self {
    self.threshold = threshold;
    self
  }

  pub const fn with_salt(mut self, salt: [u8; 32]) -> Self {
    self.salt = Some(salt);
    self
  }

  pub fn with_factor<F: Into<Material>>(mut self, factor: F) -> Self {
    self.factors.push(factor.into());
    self
  }

  // TODO (autoparallel): This is a **minimal** implementation (no integrity HMAC yet).
  pub fn build(self) -> MFKDF2Result<(Policy, [u8; 32])> {
    // Check threshold against number of factors
    // TODO (autoparallel): This should be compile-time checkable? Or at least an error.
    if !(1..=self.factors.len()).contains(&(self.threshold as usize)) {
      return Err(MFKDF2Error::InvalidThreshold);
    }

    // Generate salt & secret if not provided
    let salt: [u8; 32] = self.salt.unwrap_or_else(|| {
      let mut salt = [0u8; 32];
      OsRng.fill_bytes(&mut salt);
      salt
    });
    let mut secret: [u8; 32] = [0u8; 32];
    OsRng.fill_bytes(&mut secret);

    // Generate key
    let key = argon2id(&secret, &salt);

    // Split secret into Shamir shares
    let shares = split_secret(&secret, self.threshold, self.factors.len());

    // Build FactorPolicy list
    let mut factor_policies = Vec::new();
    let mut ids = HashSet::new();
    for (mat, share) in self.factors.into_iter().zip(shares) {
      // per-factor salt
      let mut salt_factor = [0u8; 32];
      OsRng.fill_bytes(&mut salt_factor);

      // HKDF stretch & AES-encrypt share
      let stretched = hkdf_sha256(&mat.data, &salt_factor);
      let pad = aes256_ecb_encrypt(&share, &stretched);

      // Generate factor key
      let key_factor = hkdf_sha256(&key, &salt_factor);
      let secret_factor = aes256_ecb_encrypt(&share, &key_factor);

      // TODO (autoparallel): Add params for each factor.
      let params = Value::Object(Map::new());

      // Generate ID if not provided
      let id = mat.id.unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(&mat.data);
        let hash = hasher.finalize();
        general_purpose::STANDARD.encode(hash)
      });

      if !ids.insert(id.clone()) {
        return Err(MFKDF2Error::DuplicateFactorId);
      }

      factor_policies.push(Factor {
        id,
        kind: mat.kind,
        pad: general_purpose::STANDARD.encode(pad),
        salt: general_purpose::STANDARD.encode(salt_factor),
        key: key_factor,
        secret: secret_factor,
        params,
      });
    }

    // Derive an integrity key specific to the policy and compute a policy HMAC
    let integrity_key = hkdf_sha256(&key, &salt);

    // Hash the signable policy components (threshold, salt, factors) to match JS `extract`
    let encoded_salt = general_purpose::STANDARD.encode(salt);
    let mut hasher = Sha256::new();
    hasher.update(self.threshold.to_le_bytes());
    hasher.update(encoded_salt.as_bytes());
    // Serialize factors deterministically so the same digest is produced
    let factors_json = serde_json::to_string(&factor_policies).expect("serialize factors");
    hasher.update(factors_json.as_bytes());
    let policy_data = hasher.finalize();

    let mut mac = Hmac::<Sha256>::new_from_slice(&integrity_key).expect("HMAC init");
    mac.update(policy_data.as_slice());
    let result = mac.finalize();
    let mut integrity = [0u8; 32];
    integrity.copy_from_slice(&result.into_bytes());

    Ok((
      Policy {
        threshold: self.threshold,
        salt: general_purpose::STANDARD.encode(salt),
        factors: factor_policies,
        integrity,
      },
      key,
    ))
  }
}

// TODO (autoparallel): Add a `PolicyBuilder` to make it easier to create policies.
impl Policy {
  // TODO (autoparallel): We should have some kind of introspection on what we can derive from. So
  // we should have some kind of `Policy::derive_from` that takes a single typed factor and the
  // stage of "how derived" the policy is. Could have `PolicyInteractive` or something like that to
  // make this nicer. Idk.
  pub fn derive(&self, factors: impl IntoIterator<Item = Material>) -> MFKDF2Result<[u8; 32]> {
    let mut shares_bytes = Vec::new();
    for factor in factors {
      if factor.id.is_none() {
        return Err(MFKDF2Error::MissingFactorId);
      }

      if let Some(factor_policy) =
        // Note: This unwrap is safe because we checked that the id is not none above.
        self.factors.iter().find(|&f| f.id == *factor.id.as_ref().unwrap())
      {
        // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
        let salt_bytes = general_purpose::STANDARD.decode(&factor_policy.salt)?;
        let salt_arr: [u8; 32] = salt_bytes.try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;

        let stretched = hkdf_sha256(&factor.data, &salt_arr);

        // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
        let pad = general_purpose::STANDARD.decode(&factor_policy.pad)?;
        let plaintext = aes256_ecb_decrypt(pad, &stretched);

        // TODO (autoparallel): It would be preferred to know the size of this array at compile
        // time.
        shares_bytes.push(plaintext);
      }
    }

    let shares_vec: Vec<Share> = shares_bytes
      .iter()
      .map(|b| Share::try_from(&b[..]).map_err(|_| MFKDF2Error::TryFromVecError))
      .collect::<Result<Vec<Share>, _>>()?;

    let sharks = Sharks(self.threshold);
    let secret = sharks.recover(&shares_vec).map_err(|_| MFKDF2Error::ShareRecoveryError)?;
    let secret_arr: [u8; 32] = secret[..32].try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;

    let salt_bytes = general_purpose::STANDARD.decode(&self.salt)?;
    let salt_arr: [u8; 32] = salt_bytes.try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;
    let key = argon2id(&secret_arr, &salt_arr);
    Ok(key)
  }
}

#[cfg(test)]
mod tests {
  #![allow(clippy::unwrap_used)]
  #![allow(clippy::expect_used)]

  use itertools::Itertools;

  use super::*;
  use crate::factors::{password::Password, question::Question, uuid::Uuid};

  fn password() -> Password { Password::new("hunter2").unwrap() }

  fn question() -> Question { Question::new("What is the capital of France?", "Paris").unwrap() }

  fn uuid() -> Uuid { Uuid::from_u128(123_456_789_012) }

  fn factors() -> Vec<Material> {
    let mut password: Material = password().into();
    password.set_id("password1");
    let mut question: Material = question().into();
    question.set_id("question1");
    let mut uuid: Material = uuid().into();
    uuid.set_id("uuid1");
    vec![password, question, uuid]
  }

  fn policy_3_of_3() -> (Policy, [u8; 32]) {
    PolicyBuilder::new()
      .with_threshold(3)
      .with_factor(factors()[0].clone())
      .with_factor(factors()[1].clone())
      .with_factor(factors()[2].clone())
      .build()
      .expect("build should succeed")
  }

  fn policy_2_of_3() -> (Policy, [u8; 32]) {
    PolicyBuilder::new()
      .with_threshold(2)
      .with_factor(factors()[0].clone())
      .with_factor(factors()[1].clone())
      .with_factor(factors()[2].clone())
      .build()
      .expect("build should succeed")
  }

  fn policy_1_of_3() -> (Policy, [u8; 32]) {
    PolicyBuilder::new()
      .with_threshold(1)
      .with_factor(factors()[0].clone())
      .with_factor(factors()[1].clone())
      .with_factor(factors()[2].clone())
      .build()
      .expect("build should succeed")
  }

  #[test]
  fn setup_generates_policy() {
    let (policy, _) = policy_3_of_3();

    assert_eq!(policy.threshold, 3);
    assert_eq!(policy.factors.len(), 3);

    for f in &policy.factors {
      assert!(!f.pad.is_empty());
      assert!(!f.salt.is_empty());
    }
  }

  #[test]
  fn setup_then_derive() {
    let factors = factors();
    let (policy, key) = policy_3_of_3();

    let key_derived = policy.derive(factors).expect("derive should succeed");
    assert_eq!(key_derived, key);
  }

  #[test]
  fn derive_fails_with_insufficient_factors_3_of_3() {
    let (policy, _) = policy_3_of_3();
    let all = factors();
    let n = all.len();

    // sizes 0,1,2 are insufficient when threshold is 3
    for k in 1..3 {
      for idxs in (0..n).combinations(k) {
        let subset: Vec<Material> = idxs.iter().map(|&i| all[i].clone()).collect();
        assert_eq!(policy.derive(subset).unwrap_err(), MFKDF2Error::ShareRecoveryError);
      }
    }
  }

  #[test]
  fn derive_fails_with_insufficient_factors_2_of_3() {
    let (policy, _) = policy_2_of_3();
    let all = factors();
    let n = all.len();

    // sizes 0,1 are insufficient when threshold is 2
    for k in 1..2 {
      for idxs in (0..n).combinations(k) {
        let subset: Vec<Material> = idxs.iter().map(|&i| all[i].clone()).collect();
        assert_eq!(policy.derive(subset).unwrap_err(), MFKDF2Error::ShareRecoveryError);
      }
    }
  }

  #[test]
  fn derive_fails_with_insufficient_factors_1_of_3() {
    let (policy, _) = policy_1_of_3();

    // empty set is insufficient when threshold is 1
    assert_eq!(policy.derive(Vec::<Material>::new()).unwrap_err(), MFKDF2Error::ShareRecoveryError);
  }

  #[test]
  fn derive_panics_with_incorrect_factor() {
    let factors = factors();
    let (policy, key) = policy_3_of_3();

    // flip a byte in one factor to simulate wrong password
    let mut bad_factors = factors;
    bad_factors[0].data[0] ^= 0xFF;

    let key_derived = policy.derive(bad_factors).expect("derive should succeed");
    assert_ne!(key_derived, key);
  }

  #[test]
  fn threshold_1_of_3() {
    let all = factors();
    let (policy, key) = policy_1_of_3();

    // key derived with all factors (ground truth)
    let key_correct = policy.derive(all.clone()).expect("derive should succeed");
    assert_eq!(key_correct, key);

    let n = all.len();
    // Every non-empty subset (sizes 1..=3) should succeed and equal `key`
    for k in 1..=all.len() {
      for idxs in (0..n).combinations(k) {
        let subset: Vec<Material> = idxs.iter().map(|&i| all[i].clone()).collect();
        let derived = policy.derive(subset).expect("derive should succeed");
        assert_eq!(derived, key);
      }
    }
  }

  #[test]
  fn threshold_2_of_3() {
    let all = factors();
    let (policy, key) = policy_2_of_3();

    let n = all.len();

    // Subsets of size 2 or 3 should derive the same key.
    for k in 2..=n {
      for idxs in (0..n).combinations(k) {
        let subset: Vec<Material> = idxs.iter().map(|&i| all[i].clone()).collect();
        let derived = policy.derive(subset).expect("derive should succeed");
        assert_eq!(derived, key);
      }
    }
  }

  #[test]
  fn serialize_deserialize() {
    let (policy, _) = policy_3_of_3();

    let serialized = serde_json::to_string_pretty(&policy).expect("serialize should succeed");
    let deserialized: Policy =
      serde_json::from_str(&serialized).expect("deserialize should succeed");
    assert_eq!(policy.threshold, deserialized.threshold);
    assert_eq!(policy.factors.len(), deserialized.factors.len());
    for (p, d) in policy.factors.iter().zip(deserialized.factors.iter()) {
      assert_eq!(p.id, d.id);
      assert_eq!(p.kind, d.kind);
      assert_eq!(p.pad, d.pad);
    }
    assert_eq!(policy.integrity, deserialized.integrity);
  }

  #[test]
  fn policy_from_typed_factors() {
    let (policy, _) = PolicyBuilder::new()
      .with_threshold(3)
      .with_factor(password())
      .with_factor(question())
      .with_factor(uuid())
      .build()
      .expect("build should succeed");

    assert_eq!(policy.threshold, 3);
    assert_eq!(policy.factors.len(), 3);

    for f in &policy.factors {
      assert!(!f.pad.is_empty());
      assert!(!f.salt.is_empty());
    }
  }
}
