use std::collections::HashMap;

use base64::{Engine, engine::general_purpose};
use sharks::{Share, Sharks};

use crate::{
  crypto::{aes256_ecb_decrypt, balloon_sha3_256, hkdf_sha256},
  derive::DeriveFactorFn,
  error::{MFKDF2Error, MFKDF2Result},
  setup::key::{MFKDF2DerivedKey, MFKDF2Entropy, Policy},
};

pub async fn key(
  policy: Policy,
  factors: HashMap<String, DeriveFactorFn>,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut shares_bytes = Vec::new();
  for factor in policy.clone().factors {
    let factor_fn = match factors.get(factor.id.as_str()) {
      Some(factor_fn) => factor_fn,
      None => continue,
    };

    let material = factor_fn(serde_json::from_str(&factor.params).unwrap()).await?;

    // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
    let salt_bytes = general_purpose::STANDARD.decode(&factor.salt)?;
    let salt_arr: [u8; 32] = salt_bytes.try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;

    let stretched = hkdf_sha256(&material.data, &salt_arr);

    // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
    let pad = general_purpose::STANDARD.decode(&factor.pad)?;
    let plaintext = aes256_ecb_decrypt(pad, &stretched);

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
  let key = balloon_sha3_256(&secret_arr, &salt_arr);

  // TODO (autoparallel): Properly update the policy.
  Ok(MFKDF2DerivedKey {
    policy,
    key,
    secret: secret_arr,
    shares: shares_vec.into_iter().map(|s| Vec::from(&s)).collect(),
    outputs: Vec::new(),
    entropy: MFKDF2Entropy { real: 0, theoretical: 0 },
  })
}
