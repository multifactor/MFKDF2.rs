// TODO (autoparallel): If we use `no-std`, then this use of `HashSet` will need to be
// replaced.
use std::collections::{HashMap, HashSet};

use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssskit::{SecretSharing, Share};
use uuid::Uuid;

use crate::{
  constants::SECRET_SHARING_POLY,
  crypto::{encrypt, hkdf_sha256_with_info, hmacsha256},
  definitions::{MFKDF2DerivedKey, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  policy::Policy,
  setup::FactorSetup,
};

// TODO (autoparallel): We probably can just use the MFKDF2Factor struct directly here.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct PolicyFactor {
  pub id:     String,
  #[serde(rename = "type")]
  pub kind:   String,
  pub pad:    String,
  pub salt:   String,
  pub secret: String,
  // TODO (@lonerapier): convert it into a factor based enum
  pub params: Value,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub hint:   Option<String>,
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Serialize, Deserialize)]
pub struct MFKDF2Options {
  pub id:        Option<String>,
  pub threshold: Option<u8>,
  // TODO (@lonerapier): use uniffi custom type
  pub salt:      Option<Vec<u8>>,
  pub stack:     Option<bool>,
  pub integrity: Option<bool>,
  pub time:      Option<u32>,
  pub memory:    Option<u32>,
}

impl Default for MFKDF2Options {
  fn default() -> Self {
    let mut salt = [0u8; 32];
    crate::rng::fill_bytes(&mut salt);

    Self {
      id:        Some(uuid::Uuid::new_v4().to_string()),
      threshold: None,
      salt:      Some(salt.to_vec()),
      stack:     None,
      integrity: Some(true),
      time:      Some(0),
      memory:    Some(0),
    }
  }
}

pub fn key(factors: Vec<MFKDF2Factor>, options: MFKDF2Options) -> MFKDF2Result<MFKDF2DerivedKey> {
  // Sets the threshold to be the number of factors (n of n) if not provided.
  let threshold = options.threshold.unwrap_or(factors.len() as u8);

  // Check threshold against number of factors
  // TODO (autoparallel): This should be compile-time checkable? Or at least an error.
  if factors.is_empty() || threshold as usize == 0 || threshold as usize > factors.len() {
    return Err(MFKDF2Error::InvalidThreshold);
  }

  // Generate salt & secret if not provided
  let salt: Vec<u8> = match options.salt {
    Some(salt) => salt,
    None => {
      let mut salt = [0u8; 32];
      crate::rng::fill_bytes(&mut salt);
      salt.to_vec()
    },
  };

  let policy_id = if let Some(id) = options.id.clone() {
    if id.is_empty() {
      return Err(MFKDF2Error::MissingFactorId);
    }
    id
  } else {
    Uuid::new_v4().to_string()
  };

  // time
  let time = options.time.unwrap_or(0);

  // memory
  let memory = options.memory.unwrap_or(0);

  // master secret
  let mut secret: [u8; 32] = [0u8; 32];
  crate::rng::fill_bytes(&mut secret);

  let mut key = [0u8; 32];
  crate::rng::fill_bytes(&mut key);

  // Generate key
  let mut kek = [0u8; 32];
  if options.stack.unwrap_or(false) {
    // stack key
    kek = hkdf_sha256_with_info(&secret, &salt, format!("mfkdf2:stack:{}", policy_id).as_bytes());
  } else {
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
  }

  // policy key
  let policy_key = encrypt(&key, &kek);

  // Split secret into Shamir shares
  let dealer =
    SecretSharing::<SECRET_SHARING_POLY>(threshold).dealer_rng(&secret, &mut crate::rng::GlobalRng);
  let shares: Vec<Vec<u8>> =
    dealer.take(factors.len()).map(|s: Share<SECRET_SHARING_POLY>| Vec::from(&s)).collect();

  let mut policy_factors = Vec::new();
  let mut ids = HashSet::new();
  let mut outputs = HashMap::new();
  let mut theoretical_entropy: Vec<u32> = Vec::new();
  let mut real_entropy: Vec<f64> = Vec::new();

  for (factor, share) in factors.iter().zip(shares.iter()) {
    // Factor id uniqueness
    let id = factor.id.clone();
    if !ids.insert(id.clone()) {
      return Err(MFKDF2Error::DuplicateFactorId);
    }
    let id = id.unwrap();

    let mut salt = [0u8; 32];
    crate::rng::fill_bytes(&mut salt);

    // HKDF stretch & AES-encrypt share
    let stretched =
      hkdf_sha256_with_info(&factor.data(), &salt, format!("mfkdf2:factor:pad:{}", &id).as_bytes());
    let pad = encrypt(share, &stretched);

    // Generate factor key
    let params_key =
      hkdf_sha256_with_info(&key, &salt, format!("mfkdf2:factor:params:{}", &id).as_bytes());

    let params = factor.factor_type.setup().params(params_key.into())?;
    // TODO (autoparallel): This should not be an unwrap.
    outputs.insert(id.clone(), factor.factor_type.output());

    let secret_key =
      hkdf_sha256_with_info(&key, &salt, format!("mfkdf2:factor:secret:{}", &id).as_bytes());
    let factor_secret = encrypt(&stretched, &secret_key);

    // Record entropy statistics (in bits) for this factor.
    theoretical_entropy.push(factor.data().len() as u32 * 8);
    // TODO (autoparallel): This should not be an unwrap, should entropy really be optional?
    real_entropy.push(factor.entropy.unwrap());

    policy_factors.push(PolicyFactor {
      id,
      kind: factor.kind(),
      pad: general_purpose::STANDARD.encode(pad),
      salt: general_purpose::STANDARD.encode(salt),
      secret: general_purpose::STANDARD.encode(factor_secret),
      params,
      hint: None,
    });
  }

  let mut policy = Policy {
    schema: "https://mfkdf.com/schema/v2.0.0/policy.json".to_string(),
    id: policy_id,
    threshold,
    salt: general_purpose::STANDARD.encode(&salt),
    factors: policy_factors,
    hmac: "".to_string(),
    time,
    memory,
    key: general_purpose::STANDARD.encode(policy_key),
  };

  // Derive an integrity key specific to the policy and compute a policy HMAC
  if options.integrity.unwrap_or(true) {
    let integrity_data = policy.extract();
    let integrity_key = hkdf_sha256_with_info(&key, &salt, "mfkdf2:integrity".as_bytes());
    let digest = hmacsha256(&integrity_key, &integrity_data);
    policy.hmac = general_purpose::STANDARD.encode(digest);
  }

  // Calculate entropy
  theoretical_entropy.sort_unstable();
  real_entropy.sort_unstable_by(f64::total_cmp);

  let theoretical_sum: u32 = theoretical_entropy.into_iter().take(threshold as usize).sum();
  let real_sum: f64 = real_entropy.into_iter().take(threshold as usize).sum();

  let entropy_theoretical = theoretical_sum.min(256);
  let entropy_real = real_sum.min(256.0);

  Ok(MFKDF2DerivedKey {
    policy,
    key: key.into(),
    secret: secret.to_vec(),
    shares,
    outputs,
    entropy: crate::definitions::MFKDF2Entropy {
      real:        entropy_real,
      theoretical: entropy_theoretical,
    },
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn setup_key(
  factors: Vec<MFKDF2Factor>,
  options: MFKDF2Options,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  key(factors, options)
}

#[cfg(test)]
mod tests {
  use rstest::rstest;

  use super::*;
  use crate::{
    crypto::decrypt,
    setup::factors::{
      hmacsha1::{HmacSha1Options, hmacsha1},
      hotp::{HOTPOptions, hotp},
      password::{PasswordOptions, password},
      question::{QuestionOptions, question},
      totp::{TOTPOptions, totp},
      uuid::{UUIDOptions, uuid},
    },
  };

  const HMACSHA1_SECRET: [u8; 20] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
  ];

  fn generate_factors(num: usize) -> Vec<MFKDF2Factor> {
    let mut factors =
      vec![password("password123", PasswordOptions { id: Some("pw".to_string()) }).unwrap()];

    factors.push(
      hmacsha1(HmacSha1Options {
        id:     Some("hmac".to_string()),
        secret: Some(HMACSHA1_SECRET.to_vec()),
      })
      .unwrap(),
    );

    factors.push(hotp(HOTPOptions { id: Some("hotp".to_string()), ..Default::default() }).unwrap());

    factors.push(totp(TOTPOptions { id: Some("totp".to_string()), ..Default::default() }).unwrap());

    factors.push(
      question("an answer", QuestionOptions {
        id: Some("question".to_string()),
        ..Default::default()
      })
      .unwrap(),
    );

    factors.push(uuid(UUIDOptions { id: Some("uuid".to_string()), ..Default::default() }).unwrap());

    factors.into_iter().take(num).collect()
  }

  #[rstest]
  #[case::password_only(vec![password("password123", PasswordOptions::default()).unwrap()])]
  #[case::hmacsha1_only(vec![hmacsha1(HmacSha1Options {
    id:     Some("hmacsha1".to_string()),
    secret: Some(HMACSHA1_SECRET.to_vec()),
  })
  .unwrap()])]
  #[case::password_and_hmacsha1(vec![
    password("password123", PasswordOptions::default()).unwrap(),
    hmacsha1(HmacSha1Options {
      id:     Some("hmacsha1".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    })
    .unwrap()
  ])]
  #[case::all_three(vec![
    password("password123", PasswordOptions::default()).unwrap(),
    hmacsha1(HmacSha1Options {
      id:     Some("hmacsha1".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    })
    .unwrap(),
    hotp(HOTPOptions::default()).unwrap()
  ])]
  #[case::totp_only(vec![totp(TOTPOptions::default()).unwrap()])]
  #[case::password_and_totp(vec![
    password("password123", PasswordOptions::default()).unwrap(),
    totp(TOTPOptions::default()).unwrap()
  ])]
  #[case::all_four(vec![
    password("password123", PasswordOptions::default()).unwrap(),
    hmacsha1(HmacSha1Options {
      id:     Some("hmacsha1".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    })
    .unwrap(),
    hotp(HOTPOptions::default()).unwrap(),
    totp(TOTPOptions::default()).unwrap()
  ])]
  #[case::question_only(vec![question("my secret answer", QuestionOptions::default()).unwrap()])]
  #[case::uuid_only(vec![uuid(UUIDOptions::default()).unwrap()])]
  #[test]
  fn key_construction(#[case] factors: Vec<MFKDF2Factor>) {
    let options = MFKDF2Options::default();
    let derived_key = key(factors.clone(), options.clone()).unwrap();

    let salt = general_purpose::STANDARD.decode(derived_key.policy.salt.clone()).unwrap();
    let mut kek = [0u8; 32];
    Argon2::new(
      argon2::Algorithm::Argon2id,
      Version::default(),
      Params::new(
        argon2::Params::DEFAULT_M_COST + options.memory.unwrap(),
        argon2::Params::DEFAULT_T_COST + options.time.unwrap(),
        1,
        Some(32),
      )
      .unwrap(),
    )
    .hash_password_into(&derived_key.secret, &salt, &mut kek)
    .unwrap();

    let policy_key = general_purpose::STANDARD.decode(derived_key.policy.key.clone()).unwrap();
    let key = decrypt(policy_key, &kek);

    assert_eq!(derived_key.policy.id, options.id.unwrap());
    assert_eq!(derived_key.policy.threshold as usize, factors.len());
    assert_eq!(derived_key.policy.salt, general_purpose::STANDARD.encode(options.salt.unwrap()));
    assert_eq!(derived_key.policy.time, options.time.unwrap());
    assert_eq!(derived_key.policy.memory, options.memory.unwrap());

    assert_eq!(derived_key.key, key.clone().try_into().unwrap());

    // verify factor secret is encrypted with key
    let mut shares = Vec::new();
    for factor in &derived_key.policy.factors {
      let secret_key = hkdf_sha256_with_info(
        &key,
        &general_purpose::STANDARD.decode(factor.salt.clone()).unwrap(),
        format!("mfkdf2:factor:secret:{}", &factor.id).as_bytes(),
      );
      let factor_secret = general_purpose::STANDARD.decode(factor.secret.clone()).unwrap();
      let stretched = decrypt(factor_secret, &secret_key).try_into().unwrap();

      let pad = general_purpose::STANDARD.decode(factor.pad.clone()).unwrap();
      let factor_share = decrypt(pad, &stretched);

      shares.push(factor_share);
    }

    // combine shares to get secret
    let shares_vec: Vec<Option<Share<SECRET_SHARING_POLY>>> =
      shares.into_iter().map(|b| Some(Share::try_from(b.as_slice()).unwrap())).collect();

    let sss = SecretSharing(derived_key.policy.threshold);
    let secret = sss.recover(&shares_vec).unwrap();

    assert_eq!(secret[..32], derived_key.secret);
  }

  #[rstest]
  #[case(3, 1)]
  #[case(3, 2)]
  #[case(3, 3)]
  #[case(5, 2)]
  #[case(5, 5)]
  #[test]
  fn key_construction_with_threshold(#[case] num_factors: usize, #[case] threshold: u8) {
    let factors = generate_factors(num_factors);
    let options = MFKDF2Options { threshold: Some(threshold), ..Default::default() };

    let derived_key = key(factors.clone(), options.clone()).unwrap();

    assert_eq!(derived_key.policy.threshold, threshold);

    let salt = general_purpose::STANDARD.decode(derived_key.policy.salt.clone()).unwrap();
    let mut kek = [0u8; 32];
    Argon2::new(
      argon2::Algorithm::Argon2id,
      Version::default(),
      Params::new(
        argon2::Params::DEFAULT_M_COST + options.memory.unwrap(),
        argon2::Params::DEFAULT_T_COST + options.time.unwrap(),
        1,
        Some(32),
      )
      .unwrap(),
    )
    .hash_password_into(&derived_key.secret, &salt, &mut kek)
    .unwrap();

    let policy_key = general_purpose::STANDARD.decode(derived_key.policy.key.clone()).unwrap();
    let key = decrypt(policy_key, &kek);
    assert_eq!(derived_key.key, key.clone().try_into().unwrap());

    let shares_to_recover: Vec<Vec<u8>> =
      derived_key.shares.iter().take(threshold as usize).cloned().collect();

    let shares_vec: Vec<Option<Share<SECRET_SHARING_POLY>>> =
      shares_to_recover.iter().map(|b| Some(Share::try_from(&b[..]).unwrap())).collect();

    let sss = SecretSharing(threshold);
    let recovered_secret = sss.recover(&shares_vec).unwrap();

    assert_eq!(recovered_secret[..32], derived_key.secret);
  }

  #[rstest]
  #[case(3, 0)]
  #[case(3, 4)]
  #[case(0, 0)]
  #[test]
  fn key_construction_with_invalid_threshold(#[case] num_factors: usize, #[case] threshold: u8) {
    let factors = generate_factors(num_factors);
    let options = MFKDF2Options { threshold: Some(threshold), ..Default::default() };
    let derived_key_result = key(factors.clone(), options.clone());

    assert!(matches!(derived_key_result, Err(MFKDF2Error::InvalidThreshold)));
  }
}
