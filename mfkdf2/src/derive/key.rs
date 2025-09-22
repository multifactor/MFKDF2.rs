use std::collections::HashMap;

use argon2::Argon2;
use base64::{Engine, engine::general_purpose};
use sharks::{Share, Sharks};

use crate::{
  crypto::{decrypt, hkdf_sha256},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::{
    factors::{FactorSetup, MFKDF2Factor},
    key::{MFKDF2DerivedKey, MFKDF2Entropy, Policy},
  },
};

pub fn key(
  policy: Policy,
  factors: HashMap<String, MFKDF2Factor>,
  verify: bool,
  stack: bool,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut shares_bytes = Vec::new();
  for factor in policy.clone().factors {
    let mut material = match factors.get(factor.id.as_str()).cloned() {
      Some(material) => material,
      None => continue,
    };

    material.factor_type.include_params(serde_json::from_str(&factor.params).unwrap())?;

    // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
    let salt_bytes = general_purpose::STANDARD.decode(&factor.salt)?;
    let salt_arr: [u8; 32] = salt_bytes.try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;

    let stretched = hkdf_sha256(&material.factor_type.bytes(), &salt_arr);

    // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
    let pad = general_purpose::STANDARD.decode(&factor.pad)?;
    let plaintext = decrypt(pad, &stretched);

    // TODO (autoparallel): It would be preferred to know the size of this array at compile
    // time.
    shares_bytes.push(plaintext);
  }

  let shares_vec: Vec<Share> = shares_bytes
    .iter()
    .map(|b| Share::try_from(&b[..]).map_err(|_| MFKDF2Error::TryFromVecError))
    .collect::<Result<Vec<Share>, _>>()?;

  let sharks = Sharks(policy.threshold);
  let secret = sharks.recover(&shares_vec).map_err(|_| MFKDF2Error::ShareRecoveryError)?;
  let secret_arr: [u8; 32] = secret[..32].try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;

  let salt_bytes = general_purpose::STANDARD.decode(&policy.salt)?;
  let salt_arr: [u8; 32] = salt_bytes.try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;
  let mut key = [0u8; 32];
  Argon2::default().hash_password_into(&secret_arr, &salt_arr, &mut key)?;

  // TODO (autoparallel): Properly update the policy.

  Ok(MFKDF2DerivedKey {
    policy,
    key: key.to_vec(),
    secret: secret_arr.to_vec(),
    shares: shares_vec.into_iter().map(|s| Vec::from(&s)).collect(),
    outputs: Vec::new(),
    entropy: MFKDF2Entropy { real: 0, theoretical: 0 },
  })
}

#[uniffi::export]
pub fn derive_key(
  policy: Policy,
  factors: HashMap<String, MFKDF2Factor>,
  verify: bool,
  stack: bool,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  // Reuse the existing constructor logic
  key(policy, factors, verify, stack)
}
