use base64::{Engine, engine::general_purpose};
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
  pub fn build(self) -> MFKDF2Result<Policy> {
    // Check threshold against number of factors
    // TODO (autoparallel): This should be compile-time checkable? Or at least an error.
    if !(1..=self.factors.len()).contains(&(self.threshold as usize)) {
      return Err(MFKDF2Error::InvalidThreshold);
    }

    // Generate global salt & secret if not provided
    let global_salt: [u8; 32] = self.salt.unwrap_or_else(|| {
      let mut salt = [0u8; 32];
      OsRng.fill_bytes(&mut salt);
      salt
    });
    let mut secret: [u8; 32] = [0u8; 32];
    OsRng.fill_bytes(&mut secret);

    // Split secret into Shamir shares
    let shares = split_secret(&secret, self.threshold, self.factors.len());

    // Build FactorPolicy list
    let mut factor_policies = Vec::new();
    for (mat, share) in self.factors.into_iter().zip(shares) {
      // per-factor salt
      let mut salt_bytes = [0u8; 32];
      OsRng.fill_bytes(&mut salt_bytes);

      // HKDF stretch & AES-encrypt share
      let stretched = hkdf_sha256(&mat.data, &salt_bytes);
      let pad = aes256_ecb_encrypt(&share, &stretched);

      // TODO (autoparallel): Add params for each factor.
      let params = Value::Object(Map::default());

      // Generate ID if not provided
      let id = mat.id.unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(&mat.data);
        let hash = hasher.finalize();
        general_purpose::STANDARD.encode(hash)
      });

      factor_policies.push(Factor {
        id,
        kind: mat.kind,
        pad: general_purpose::STANDARD.encode(pad),
        salt: general_purpose::STANDARD.encode(salt_bytes),
        params,
      });
    }

    Ok(Policy {
      threshold: self.threshold,
      salt:      general_purpose::STANDARD.encode(global_salt),
      factors:   factor_policies,
    })
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

  fn policy_3_of_3() -> Policy {
    PolicyBuilder::new()
      .with_threshold(3)
      .with_factor(factors()[0].clone())
      .with_factor(factors()[1].clone())
      .with_factor(factors()[2].clone())
      .build()
      .expect("build should succeed")
  }

  fn policy_2_of_3() -> Policy {
    PolicyBuilder::new()
      .with_threshold(2)
      .with_factor(factors()[0].clone())
      .with_factor(factors()[1].clone())
      .with_factor(factors()[2].clone())
      .build()
      .expect("build should succeed")
  }

  fn policy_1_of_3() -> Policy {
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
    let policy = policy_3_of_3();

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
    let policy = policy_3_of_3();

    let key = policy.derive(factors).expect("derive should succeed");
    assert_eq!(key.len(), 32);
  }

  #[test]
  #[should_panic(expected = "Not enough shares to recover original secret")]
  fn derive_fails_with_insufficient_factors_3_of_3() {
    let policy = policy_3_of_3();

    // Drop the last factor to make it insufficient
    let mut insufficient_factors = factors();
    insufficient_factors.pop();

    let _result = policy.derive(insufficient_factors).expect("derive should succeed");
  }

  #[test]
  #[should_panic(expected = "Not enough shares to recover original secret")]
  fn derive_fails_with_insufficient_factors_2_of_3() {
    let setup_factors = factors();
    let policy = policy_2_of_3();

    let mut insufficient_factors = setup_factors;
    insufficient_factors.pop();
    insufficient_factors.pop();

    let _result = policy.derive(insufficient_factors).expect("derive should succeed");
  }

  #[test]
  #[should_panic(expected = "Not enough shares to recover original secret")]
  fn derive_fails_with_insufficient_factors_1_of_3() {
    let setup_factors = factors();
    let policy = policy_1_of_3();

    let mut insufficient_factors = setup_factors;
    insufficient_factors.pop();
    insufficient_factors.pop();
    insufficient_factors.pop();

    let _result = policy.derive(insufficient_factors).expect("derive should succeed");
  }

  #[test]
  fn derive_panics_with_incorrect_factor() {
    let factors = factors();
    let policy = policy_3_of_3();

    let key_correct = policy.derive(factors.clone()).expect("derive should succeed");

    // flip a byte in one factor to simulate wrong password
    let mut bad_factors = factors;
    bad_factors[0].data[0] ^= 0xFF;

    let key = policy.derive(bad_factors).expect("derive should succeed");
    assert_ne!(key, key_correct);
  }

  #[test]
  fn threshold_1_of_3() {
    let factors = factors();
    let policy = policy_1_of_3();

    let key_correct = policy.derive(factors.clone()).expect("derive should succeed");
    assert_eq!(key_correct.len(), 32);

    // Try with just password
    let key_from_password = policy.derive(factors[0].clone()).expect("derive should succeed");
    assert_eq!(key_from_password, key_correct);

    // Try with just question
    let key_from_question = policy.derive(factors[1].clone()).expect("derive should succeed");
    assert_eq!(key_from_question, key_correct);

    // Try with just uuid
    let key_from_uuid = policy.derive(factors[2].clone()).expect("derive should succeed");
    assert_eq!(key_from_uuid, key_correct);

    // Try with password and question
    let key_from_password_and_question =
      policy.derive(vec![factors[0].clone(), factors[1].clone()]).expect("derive should succeed");
    assert_eq!(key_from_password_and_question, key_correct);

    // Try with password and uuid
    let key_from_password_and_uuid =
      policy.derive(vec![factors[0].clone(), factors[2].clone()]).expect("derive should succeed");
    assert_eq!(key_from_password_and_uuid, key_correct);

    // Try with question and uuid
    let key_from_question_and_uuid =
      policy.derive(vec![factors[1].clone(), factors[2].clone()]).expect("derive should succeed");
    assert_eq!(key_from_question_and_uuid, key_correct);
  }

  #[test]
  fn threshold_2_of_3() {
    let factors = factors();
    let policy = policy_2_of_3();

    let key_correct = policy.derive(factors.clone()).expect("derive should succeed");

    // Try with password and question
    let key_from_password_and_question =
      policy.derive(vec![factors[0].clone(), factors[1].clone()]).expect("derive should succeed");
    assert_eq!(key_from_password_and_question, key_correct);

    // Try with password and uuid
    let key_from_password_and_uuid =
      policy.derive(vec![factors[0].clone(), factors[2].clone()]).expect("derive should succeed");
    assert_eq!(key_from_password_and_uuid, key_correct);

    // Try with question and uuid
    let key_from_question_and_uuid =
      policy.derive(vec![factors[1].clone(), factors[2].clone()]).expect("derive should succeed");
    assert_eq!(key_from_question_and_uuid, key_correct);
  }

  #[test]
  fn serialize_deserialize() {
    let policy = policy_3_of_3();

    let serialized = serde_json::to_string_pretty(&policy).expect("serialize should succeed");
    let deserialized: Policy =
      serde_json::from_str(&serialized).expect("deserialize should succeed");
    assert_eq!(policy, deserialized);
  }

  #[test]
  fn policy_from_typed_factors() {
    let policy = PolicyBuilder::new()
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
