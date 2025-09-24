use std::collections::HashMap;

use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose};
use sharks::{Share, Sharks};

use crate::{
  classes::mfkdf_derived_key::MFKDF2DerivedKey,
  crypto::{decrypt, hkdf_sha256_with_info, hmacsha256},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  policy::Policy,
  setup::{
    factors::{FactorSetup, MFKDF2Factor},
    key::MFKDF2Entropy,
  },
};

pub fn key(
  policy: Policy,
  factors: HashMap<String, MFKDF2Factor>,
  verify: bool,
  stack: bool,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut shares_bytes = Vec::new();
  let mut outputs = HashMap::new();

  for factor in policy.clone().factors {
    let mut material = match factors.get(factor.id.as_str()).cloned() {
      Some(material) => material,
      None => continue,
    };

    if material.kind() == String::from("persisted") {
      shares_bytes.push(material.data());
    } else {
      material.factor_type.include_params(serde_json::from_str(&factor.params).unwrap())?;

      // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
      let salt_bytes = general_purpose::STANDARD.decode(&factor.salt)?;

      let stretched = hkdf_sha256_with_info(
        &material.data(),
        &salt_bytes,
        format!("mfkdf2:factor:pad:{}", factor.id).as_bytes(),
      );

      // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
      let pad = general_purpose::STANDARD.decode(&factor.pad)?;
      let plaintext = decrypt(pad, &stretched);

      if !factor.hint.is_empty() {
        let buffer = hkdf_sha256_with_info(
          &stretched,
          &material.salt,
          format!("mfkdf2:factor:hint:{}", factor.id).as_bytes(),
        );

        let binary_string: String =
          buffer.iter().map(|byte| format!("{:08b}", byte)).collect::<Vec<_>>().join("");

        // Take the last `hint_len` characters
        let hint = binary_string
          .chars()
          .rev()
          .take(factor.hint.len())
          .collect::<Vec<_>>()
          .into_iter()
          .rev()
          .collect::<String>();

        if hint != factor.hint {
          return Err(MFKDF2Error::HintMismatch(factor.id));
        }
      }

      // TODO (autoparallel): It would be preferred to know the size of this array at compile
      // time.
      shares_bytes.push(plaintext);
      outputs.insert(factor.id, material.factor_type.output_derive().to_string());
    }
  }

  let shares_vec: Vec<Share> = shares_bytes
    .iter()
    .map(|b| Share::try_from(&b[..]).map_err(|_| MFKDF2Error::TryFromVecError))
    .collect::<Result<Vec<Share>, _>>()?;

  let sharks = Sharks(policy.threshold);
  let secret = sharks.recover(&shares_vec).map_err(|_| MFKDF2Error::ShareRecoveryError)?;
  let secret_arr: [u8; 32] = secret[..32].try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;
  let salt_bytes = general_purpose::STANDARD.decode(&policy.salt)?;

  // Generate key
  let mut kek = [0u8; 32];
  if stack {
    // stack key
    kek =
      hkdf_sha256_with_info(&secret, &salt_bytes, format!("mfkdf2:stack:{}", policy.id).as_bytes());
  } else {
    // default key
    Argon2::new(
      argon2::Algorithm::Argon2id,
      Version::default(),
      Params::new(
        argon2::Params::DEFAULT_M_COST + policy.memory,
        argon2::Params::DEFAULT_T_COST + policy.time,
        1,
        Some(32),
      )?,
    )
    .hash_password_into(&secret, &salt_bytes, &mut kek)?;
  }

  let policy_key_bytes = general_purpose::STANDARD.decode(policy.key.clone())?;
  let key = decrypt(policy_key_bytes, &kek);

  let mut new_policy = policy.clone();

  for factor in new_policy.factors.iter_mut() {
    let material = match factors.get(factor.id.as_str()).cloned() {
      Some(material) => material,
      None => continue,
    };

    let params_key = hkdf_sha256_with_info(
      &key,
      factor.salt.as_bytes(),
      format!("mfkdf2:factor:params:{}", factor.id).as_bytes(),
    );
    let params = material.factor_type.params_setup(params_key);
    factor.params = serde_json::to_string(&params)?;
  }

  if verify {
    let integrity_data = new_policy.extract();
    let integrity_key = hkdf_sha256_with_info(&key, &salt_bytes, "mfkdf2:integrity".as_bytes());
    let digest = hmacsha256(&integrity_key, &integrity_data);
    new_policy.hmac = general_purpose::STANDARD.encode(digest);
  }

  Ok(MFKDF2DerivedKey {
    policy: new_policy,
    key: key.to_vec(),
    secret: secret_arr.to_vec(),
    shares: shares_vec.into_iter().map(|s| Vec::from(&s)).collect(),
    outputs,
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
