use base64::Engine;
use serde_json::{Value, json};

use crate::{
  crypto::decrypt,
  derive::FactorDerive,
  error::MFKDF2Result,
  setup::factors::{
    Factor, FactorType, MFKDF2Factor,
    hotp::{HOTP, HOTPOptions, OTPHash, generate_hotp_code, mod_positive},
  },
};

impl FactorDerive for HOTP {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    // Store the policy parameters for derive phase
    dbg!(&params);
    self.params = serde_json::to_string(&params).unwrap();

    // If this is a derive factor (has a code), calculate target and store in options.secret
    if self.code != 0
      && let (Some(offset), Some(digits)) = (params["offset"].as_u64(), params["digits"].as_u64())
    {
      let modulus = 10_u64.pow(digits as u32);
      let target = (offset + self.code as u64) % modulus;

      // Store target as 4-byte big-endian (matches JS implementation)
      self.target = target as u32;
    }

    Ok(())
  }

  fn params_derive(&self, key: [u8; 32]) -> Value {
    // Decrypt the secret using the factor key
    let params: Value = serde_json::from_str(&self.params).unwrap();
    let pad_b64 = params["pad"].as_str().unwrap();
    let pad = base64::prelude::BASE64_STANDARD.decode(pad_b64).unwrap();
    let padded_secret = decrypt(pad, &key);

    // Generate HOTP code with incremented counter
    let counter = params["counter"].as_u64().unwrap() + 1;
    let hash = params["hash"].as_str().unwrap();
    let hash = match hash {
      "sha1" => OTPHash::Sha1,
      "sha256" => OTPHash::Sha256,
      "sha512" => OTPHash::Sha512,
      _ => panic!("Unsupported hash algorithm"),
    };
    let generated_code =
      generate_hotp_code(&padded_secret[..20], counter, &hash, self.options.digits);

    // Calculate new offset
    let new_offset = mod_positive(
      self.target as i64 - generated_code as i64,
      10_i64.pow(self.options.digits as u32),
    ) as u32;

    json!({
      "hash": hash,
      "digits": self.options.digits,
      "pad": pad_b64,
      "counter": counter,
      "offset": new_offset
    })
  }

  fn output_derive(&self, _key: [u8; 32]) -> Value { json!({}) }
}

impl Factor for HOTP {}

pub fn hotp(code: u32) -> MFKDF2Result<MFKDF2Factor> {
  // Create HOTP factor with the user-provided code
  // The target will be calculated in include_params once we have the policy parameters
  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::HOTP(HOTP {
      options: HOTPOptions::default(),
      // TODO (autoparallel): This is confusing, should probably put an Option here.
      params: serde_json::to_string(&Value::Null).unwrap(),
      code,
      target: 0,
    }),
    // TODO (autoparallel): This is confusing, should probably put an Option here.
    salt:        [0u8; 32].to_vec(),
    entropy:     Some((6_f64 * 10.0_f64.log2()) as u32),
  })
}

#[uniffi::export]
pub fn derive_hotp(code: u32) -> MFKDF2Result<MFKDF2Factor> { hotp(code) }
