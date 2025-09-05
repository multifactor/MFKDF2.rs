// TODO (autoparallel): If we use `no-std`, then this use of `HashSet` will need to be replaced.
use std::collections::HashSet;

use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};

use crate::{
  crypto::{aes256_ecb_encrypt, balloon_sha3_256, hkdf_sha256},
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::MFKDF2Factor,
};

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PolicyFactor {
  pub id:     String,
  pub kind:   String,
  pub pad:    String,
  pub salt:   String,
  pub key:    [u8; 32],
  // TODO (autoparallel): This should be a [u8; 32] instead since we're encrypting a share (16
  // bytes).
  pub secret: Vec<u8>,
  pub params: Value,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct MFKDF2Options {
  pub id:        Option<String>,
  pub threshold: Option<u8>,
  pub salt:      Option<[u8; 32]>,
  // TODO (autoparallel): Add these options.
  // pub time: Option<u32>,
  // pub memory: Option<u32>,
  // pub parallelism: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MFKDF2Entropy {
  pub real:        u32,
  pub theoretical: u32,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MFKDF2DerivedKey {
  pub policy:  Policy,
  pub key:     [u8; 32],
  pub secret:  [u8; 32],
  pub shares:  Vec<Vec<u8>>,
  pub outputs: Vec<Value>,
  pub entropy: MFKDF2Entropy,
}

impl std::fmt::Display for MFKDF2DerivedKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "MFKDF2DerivedKey {{ key: {}, secret: {} }}",
      base64::Engine::encode(&general_purpose::STANDARD, self.key),
      base64::Engine::encode(&general_purpose::STANDARD, self.secret),
    )
  }
}

pub async fn key(
  factors: Vec<MFKDF2Factor>,
  options: MFKDF2Options,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  // Sets the threshold to be the number of factors (n of n) if not provided.
  let threshold = options.clone().threshold.unwrap_or(factors.len() as u8);

  // Check threshold against number of factors
  // TODO (autoparallel): This should be compile-time checkable? Or at least an error.
  if !(1..=factors.len()).contains(&(threshold as usize)) {
    return Err(MFKDF2Error::InvalidThreshold);
  }

  // Generate salt & secret if not provided
  let salt: [u8; 32] = options.clone().salt.unwrap_or_else(|| {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
  });
  let mut secret: [u8; 32] = [0u8; 32];
  OsRng.fill_bytes(&mut secret);

  // Generate key
  let key = balloon_sha3_256(&secret, &salt);

  // Split secret into Shamir shares
  let dealer = Sharks(threshold).dealer_rng(&secret, &mut OsRng);
  let shares: Vec<Vec<u8>> = dealer.take(factors.len()).map(|s: Share| Vec::from(&s)).collect();

  let mut policy_factors = Vec::new();
  let mut ids = HashSet::new();
  let mut outputs = Vec::new();
  let mut theoretical_entropy: Vec<u32> = Vec::new();
  let mut real_entropy: Vec<u32> = Vec::new();

  for (factor, share) in factors.iter().zip(shares.clone()) {
    // HKDF stretch & AES-encrypt share
    let stretched = hkdf_sha256(&factor.data, &factor.salt);
    let pad = aes256_ecb_encrypt(&share, &stretched);

    // Generate factor key
    let key_factor = hkdf_sha256(&key, &factor.salt);
    let secret_factor = aes256_ecb_encrypt(&share, &key_factor);

    // TODO (autoparallel): Add params for each factor.
    let params = factor.params.as_ref().unwrap()().await;
    // TODO (autoparallel): This should not be an unwrap.
    outputs.push(match factor.output.as_ref() {
      Some(output) => output().await,
      None => Value::Null,
    });

    let id = factor.id.clone();

    if !ids.insert(id.clone()) {
      return Err(MFKDF2Error::DuplicateFactorId);
    }

    // Record entropy statistics (in bits) for this factor.
    theoretical_entropy.push(u32::try_from(factor.data.len() * 8).unwrap());
    // TODO (autoparallel): This should not be an unwrap, should entropy really be optional?
    real_entropy.push(factor.entropy.unwrap());

    policy_factors.push(PolicyFactor {
      id,
      kind: factor.kind.clone(),
      pad: general_purpose::STANDARD.encode(pad),
      salt: general_purpose::STANDARD.encode(factor.salt),
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
  hasher.update(threshold.to_le_bytes());
  hasher.update(encoded_salt.as_bytes());

  // Serialize factors deterministically so the same digest is produced
  let factors_json = serde_json::to_string(&factors).map_err(MFKDF2Error::SerializeError)?;
  hasher.update(factors_json.as_bytes());
  let policy_data = hasher.finalize();

  let mut mac =
    Hmac::<Sha256>::new_from_slice(&integrity_key).map_err(|_| MFKDF2Error::InvalidHmacKey)?;
  mac.update(policy_data.as_slice());
  let result = mac.finalize();
  let mut integrity = [0u8; 32];
  integrity.copy_from_slice(&result.into_bytes());

  // Calculate entropy
  theoretical_entropy.sort_unstable();
  real_entropy.sort_unstable();

  let required = threshold as usize;

  let theoretical_sum: u32 = theoretical_entropy.iter().take(required).copied().sum();
  let real_sum: u32 = real_entropy.iter().take(required).copied().sum();

  let entropy_theoretical = theoretical_sum.min(256);
  let entropy_real = real_sum.min(256);

  Ok(MFKDF2DerivedKey {
    policy: Policy {
      threshold,
      salt: general_purpose::STANDARD.encode(salt),
      factors: policy_factors,
      integrity,
    },
    key,
    secret,
    shares,
    outputs,
    entropy: MFKDF2Entropy { real: entropy_real, theoretical: entropy_theoretical },
  })
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Policy {
  pub threshold: u8,
  pub salt:      String,
  pub factors:   Vec<PolicyFactor>,
  pub integrity: [u8; 32],
}
