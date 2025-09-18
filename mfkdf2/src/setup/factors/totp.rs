use std::time::SystemTime;

use base64::Engine;
use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  crypto::encrypt,
  error::MFKDF2Result,
  setup::factors::{
    FactorTrait, FactorType, MFKDF2Factor,
    hotp::{OTPHash, generate_hotp_code},
  },
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct TOTPOptions {
  pub id:     Option<String>,
  pub secret: Option<Vec<u8>>,
  pub digits: u8,
  pub hash:   OTPHash,
  pub issuer: String,
  pub label:  String,
  pub time:   Option<SystemTime>,
  pub window: u64,
  pub step:   u64,
  pub oracle: Option<bool>, // TODO (sambhav): fix this later
}

impl Default for TOTPOptions {
  fn default() -> Self {
    Self {
      id:     Some("totp".to_string()),
      secret: None,
      digits: 6,
      hash:   OTPHash::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "mfkdf.com".to_string(),
      time:   Some(SystemTime::now()),
      window: 87600,
      step:   30,
      oracle: None,
    }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct TOTP {
  pub options: TOTPOptions,
  pub params:  String,
  pub code:    u32,
  pub target:  u32,
}

fn mod_positive(n: i64, m: i64) -> i64 { ((n % m) + m) % m }

impl FactorTrait for TOTP {
  fn kind(&self) -> String { "totp".to_string() }

  fn bytes(&self) -> Vec<u8> { self.target.to_be_bytes().to_vec() }

  fn params_setup(&self, key: [u8; 32]) -> Value {
    let time =
      self.options.time.unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
    let mut offsets = Vec::with_capacity((4 * self.options.window) as usize);
    let padded_secret = self.options.secret.as_ref().unwrap();

    for i in 0..self.options.window {
      // Calculate the time-step 'T' as per RFC 6238, Section 4.2.
      // T = floor((CurrentUnixTime - T0) / X)
      // Here, T0 is 0 (Unix epoch) and X is self.options.step.
      // We add 'i' to generate a window of future OTPs for offline use.
      let counter = (time / 1000) as u64 / self.options.step + i;
      let code =
        generate_hotp_code(&padded_secret[..20], counter, &self.options.hash, self.options.digits); // TODO (sambhav): fix this

      let offset =
        mod_positive(self.target as i64 - code as i64, 10_i64.pow(self.options.digits as u32))
          as u32;

      offsets.extend_from_slice(&offset.to_be_bytes());
    }

    let pad = encrypt(&padded_secret, &key);

    json!({
        "start": time,
        "hash": match self.options.hash {
            OTPHash::Sha1 => "sha1",
            OTPHash::Sha256 => "sha256",
            OTPHash::Sha512 => "sha512",
        },
        "digits": self.options.digits,
        "step": self.options.step,
        "window": self.options.window,
        "pad": base64::prelude::BASE64_STANDARD.encode(&pad),
        "offsets": base64::prelude::BASE64_STANDARD.encode(&offsets),
    })
  }

  fn output_setup(&self, _key: [u8; 32]) -> Value {
    json!({
      "scheme": "otpauth",
      "type": "totp",
      "label": self.options.label,
      "secret": base64::prelude::BASE64_STANDARD.encode(&self.options.secret.clone().unwrap()[..20]),
      "issuer": self.options.issuer,
      "algorithm": match self.options.hash {
        OTPHash::Sha1 => "sha1",
        OTPHash::Sha256 => "sha256",
        OTPHash::Sha512 => "sha512"
      },
      "digits": self.options.digits,
      "period": self.options.step,
      // TODO (sambhav): either generate uri yourself or use an external lib
      "uri": ""
    })
  }

  fn params_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn include_params(&mut self, _params: Value) {}
}

pub fn totp(options: TOTPOptions) -> MFKDF2Result<MFKDF2Factor> {
  let mut options = options;

  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  if options.digits < 6 || options.digits > 8 {
    return Err(crate::error::MFKDF2Error::InvalidTOTPDigits);
  }

  let secret = options.secret.unwrap_or_else(|| {
    let mut secret = vec![0u8; 20];
    OsRng.fill_bytes(&mut secret);
    secret
  });
  let mut secret_pad = [0u8; 12];
  OsRng.fill_bytes(&mut secret_pad);
  let padded_secret = secret.iter().chain(secret_pad.iter()).cloned().collect();
  options.secret = Some(padded_secret);

  if options.time.is_none() {
    options.time = Some(SystemTime::now());
  }

  // Generate random target
  let target = OsRng.gen_range(0..10_u32.pow(u32::from(options.digits)));

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  let entropy = Some((options.digits as f64 * 10.0_f64.log2()) as u32);

  Ok(MFKDF2Factor {
    id: Some(options.id.clone().unwrap_or("totp".to_string())),
    factor_type: FactorType::TOTP(TOTP {
      options,
      params: serde_json::to_string(&Value::Null).unwrap(),
      code: 0,
      target,
    }),
    salt: salt.to_vec(),
    entropy,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_totp() {}
}
