use std::collections::HashSet;

use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use rstest::{fixture, rstest};
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
  use rstest::{fixture, rstest};

  use super::*;
  use crate::factors::{password::Password, question::Question, uuid::Uuid};

  // ---------------- fixtures ----------------

  #[fixture]
  fn all_factors() -> Vec<Material> {
    let mut p: Material = Password::new("hunter2").unwrap().into();
    p.set_id("pw");
    let mut q: Material = Question::new("What is the capital of France?", "Paris").unwrap().into();
    q.set_id("qa");
    let mut u: Material = Uuid::from_u128(123_456_789_012).into();
    u.set_id("id");
    vec![p, q, u]
  }

  #[fixture]
  fn policy_1(all_factors: Vec<Material>) -> (Policy, [u8; 32]) {
    PolicyBuilder::new()
      .with_threshold(1)
      .with_factor(all_factors[0].clone())
      .with_factor(all_factors[1].clone())
      .with_factor(all_factors[2].clone())
      .build()
      .unwrap()
  }

  #[fixture]
  fn policy_2(all_factors: Vec<Material>) -> (Policy, [u8; 32]) {
    PolicyBuilder::new()
      .with_threshold(2)
      .with_factor(all_factors[0].clone())
      .with_factor(all_factors[1].clone())
      .with_factor(all_factors[2].clone())
      .build()
      .unwrap()
  }

  #[fixture]
  fn policy_3(all_factors: Vec<Material>) -> (Policy, [u8; 32]) {
    PolicyBuilder::new()
      .with_threshold(3)
      .with_factor(all_factors[0].clone())
      .with_factor(all_factors[1].clone())
      .with_factor(all_factors[2].clone())
      .build()
      .unwrap()
  }

  fn subsets(src: &[Material], k: usize) -> impl Iterator<Item = Vec<Material>> {
    (0..src.len()).combinations(k).map(|idx| idx.into_iter().map(|i| src[i].clone()).collect())
  }

  #[rstest]
  fn generates_policy(policy_3: (Policy, [u8; 32])) {
    let (p, _) = policy_3;
    assert_eq!(p.threshold, 3);
    assert_eq!(p.factors.len(), 3);
  }

  #[rstest]
  fn round_trip(policy_3: (Policy, [u8; 32]), all_factors: Vec<Material>) {
    let (p, key) = policy_3;
    assert_eq!(p.derive(all_factors).unwrap(), key);
  }

  #[rstest]
  #[case::policy_1_k_0(policy_1, 0)]
  #[case::policy_2_k_0(policy_2, 0)]
  #[case::policy_2_k_1(policy_2, 1)]
  #[case::policy_3_k_0(policy_3, 0)]
  #[case::policy_3_k_1(policy_3, 1)]
  #[case::policy_3_k_2(policy_3, 2)]
  fn insufficient(
    #[case] policy: fn(Vec<Material>) -> (Policy, [u8; 32]),
    #[case] k: usize,
    all_factors: Vec<Material>,
  ) {
    let (p, _) = policy(all_factors.clone());
    for s in subsets(&all_factors, k) {
      assert_eq!(p.derive(s).unwrap_err(), MFKDF2Error::ShareRecoveryError);
    }
  }

  #[rstest]
  #[case::policy_1(policy_1, 1)]
  #[case::policy_2(policy_2, 2)]
  #[case::policy_3(policy_3, 3)]
  fn threshold(
    #[case] policy: fn(Vec<Material>) -> (Policy, [u8; 32]),
    #[case] k: usize,
    all_factors: Vec<Material>,
  ) {
    let (p, key) = policy(all_factors.clone());
    for s in subsets(&all_factors, k) {
      assert_eq!(p.derive(s).unwrap(), key);
    }
  }
}
