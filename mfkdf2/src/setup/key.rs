// TODO (autoparallel): If we use `no-std`, then this use of `HashSet` will need to be
// replaced.
use std::collections::HashSet;

use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};
use uuid::Uuid;

use crate::{
  crypto::{encrypt, hkdf_sha256_with_info},
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorTrait, MFKDF2Factor},
};

// TODO (autoparallel): We probably can just use the MFKDF2Factor struct directly here.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PolicyFactor {
  pub id:     String,
  #[serde(rename = "type")]
  pub kind:   String,
  pub pad:    String,
  pub salt:   String,
  #[serde(skip)]
  pub key:    Vec<u8>,
  pub secret: String,
  pub params: String,
}

#[derive(Default, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct MFKDF2Options {
  pub id:        Option<String>,
  pub threshold: Option<u8>,
  pub salt:      Option<Vec<u8>>,
  pub integrity: Option<bool>,
  pub time:      Option<u32>,
  pub memory:    Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, uniffi::Record)]
pub struct MFKDF2Entropy {
  pub real:        u32,
  pub theoretical: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, uniffi::Record)]
pub struct MFKDF2DerivedKey {
  pub policy:  Policy,
  pub key:     Vec<u8>,
  pub secret:  Vec<u8>,
  pub shares:  Vec<Vec<u8>>,
  pub outputs: Vec<String>,
  pub entropy: MFKDF2Entropy,
}

impl std::fmt::Display for MFKDF2DerivedKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "MFKDF2DerivedKey {{ key: {}, secret: {} }}",
      base64::Engine::encode(&general_purpose::STANDARD, self.key.clone()),
      base64::Engine::encode(&general_purpose::STANDARD, self.secret.clone()),
    )
  }
}

#[uniffi::export]
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
  let salt: [u8; 32] = match options.clone().salt {
    Some(salt) => salt.try_into().unwrap(),
    None => {
      let mut salt = [0u8; 32];
      OsRng.fill_bytes(&mut salt);
      salt
    },
  };

  // Generate a unique ID for this policy if not provided
  let policy_id = options.id.unwrap_or_else(|| Uuid::new_v4().to_string());

  // time
  let time = options.time.unwrap_or(0);

  // memory
  let memory = options.memory.unwrap_or(0);

  // master secret
  let mut secret: [u8; 32] = [0u8; 32];
  OsRng.fill_bytes(&mut secret);

  let mut key = [0u8; 32];
  OsRng.fill_bytes(&mut key);

  // Generate key
  let mut kek = [0u8; 32];
  // TODO: stack key

  // default key
  Argon2::new(
    argon2::Algorithm::Argon2id,
    Version::default(),
    Params::new(
      argon2::Params::DEFAULT_M_COST + memory,
      argon2::Params::DEFAULT_T_COST + time,
      1,
      Some(32),
    )?,
  )
  .hash_password_into(&secret, &salt, &mut kek)?;

  // policy key
  let policy_key = encrypt(&key, &kek);

  // Split secret into Shamir shares
  let dealer = Sharks(threshold).dealer_rng(&secret, &mut OsRng);
  let shares: Vec<Vec<u8>> = dealer.take(factors.len()).map(|s: Share| Vec::from(&s)).collect();

  let mut policy_factors = Vec::new();
  let mut ids = HashSet::new();
  let mut outputs = Vec::new();
  let mut theoretical_entropy: Vec<u32> = Vec::new();
  let mut real_entropy: Vec<u32> = Vec::new();

  for (factor, share) in factors.iter().zip(shares.clone()) {
    // Factor id uniqueness
    let id = factor.id.clone();
    if !ids.insert(id.clone()) {
      return Err(MFKDF2Error::DuplicateFactorId);
    }

    // HKDF stretch & AES-encrypt share
    let stretched = hkdf_sha256_with_info(
      &factor.factor_type.bytes(),
      &factor.salt.clone().try_into().unwrap(),
      format!("mfkdf2:factor:pad:{}", &factor.id.clone().unwrap()).as_bytes(),
    );
    let pad = encrypt(&share, &stretched);

    // Generate factor key
    let params_key = hkdf_sha256_with_info(
      &key,
      &factor.salt.clone().try_into().unwrap(),
      format!("mfkdf2:factor:params:{}", &factor.id.clone().unwrap()).as_bytes(),
    );

    // TODO (autoparallel): Add params for each factor.
    let params = factor.factor_type.params_setup(params_key);
    // TODO (autoparallel): This should not be an unwrap.
    outputs.push(factor.factor_type.output_setup(key));

    let secret_key = hkdf_sha256_with_info(
      &key,
      &factor.salt.clone().try_into().unwrap(),
      format!("mfkdf2:factor:secret:{}", &factor.id.clone().unwrap()).as_bytes(),
    );
    let factor_secret = encrypt(&stretched, &secret_key);

    // Record entropy statistics (in bits) for this factor.
    theoretical_entropy.push(u32::try_from(factor.factor_type.bytes().len() * 8).unwrap());
    // TODO (autoparallel): This should not be an unwrap, should entropy really be optional?
    real_entropy.push(factor.entropy.unwrap());

    policy_factors.push(PolicyFactor {
      id:     id.unwrap(),
      kind:   factor.kind(),
      pad:    general_purpose::STANDARD.encode(pad),
      salt:   general_purpose::STANDARD.encode(factor.salt.clone()),
      key:    params_key.to_vec(), // TODO (sambhav): why is this needed?
      secret: general_purpose::STANDARD.encode(factor_secret),
      params: serde_json::to_string(&params).unwrap(),
    });
  }

  // Derive an integrity key specific to the policy and compute a policy HMAC
  let integrity_key = hkdf_sha256_with_info(&key, &salt, "mfkdf2:integrity".as_bytes());

  // Hash the signable policy components (threshold, salt, factors) to match JS `extract`
  let encoded_salt = general_purpose::STANDARD.encode(salt);
  // TODO (sambhav): add a factor extract for signing.
  let mut hasher = Sha256::new();
  hasher.update(policy_id.as_bytes());
  hasher.update(threshold.to_le_bytes());
  hasher.update(encoded_salt.as_bytes());

  // Serialize factors deterministically so the same digest is produced
  let factors_json = serde_json::to_string(&factors).map_err(MFKDF2Error::SerializeError)?;
  hasher.update(factors_json.as_bytes());
  let policy_data = hasher.finalize();

  let hmac = crate::crypto::hmacsha256(&integrity_key, policy_data.as_slice());

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
      schema: "https://mfkdf.com/schema/v2.0.0/policy.json".to_string(),
      id: policy_id,
      threshold,
      salt: general_purpose::STANDARD.encode(salt),
      factors: policy_factors,
      hmac: general_purpose::STANDARD.encode(hmac),
      time,
      memory,
      key: general_purpose::STANDARD.encode(policy_key),
    },
    key: key.to_vec(),
    secret: secret.to_vec(),
    shares,
    outputs: outputs.iter().map(|o| serde_json::to_string(o).unwrap()).collect(),
    entropy: MFKDF2Entropy { real: entropy_real, theoretical: entropy_theoretical },
  })
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, uniffi::Record)]
pub struct Policy {
  #[serde(rename = "$schema")]
  pub schema:    String,
  #[serde(rename = "$id")]
  pub id:        String,
  pub threshold: u8,
  pub salt:      String,
  pub factors:   Vec<PolicyFactor>,
  pub hmac:      String,
  pub time:      u32,
  pub memory:    u32,
  pub key:       String,
}
