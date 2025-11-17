use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(target_arch = "wasm32")]
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{
  crypto::encrypt,
  definitions::{FactorMetadata, FactorType, Key, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  otpauth::{self, HashAlgorithm, OtpauthUrlOptions, generate_hotp_code},
  setup::FactorSetup,
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTPOptions {
  pub id:     Option<String>,
  pub secret: Option<Vec<u8>>,
  pub digits: u8,
  pub hash:   HashAlgorithm,
  pub issuer: String,
  pub label:  String,
  pub time:   Option<u64>, // Unix epoch time in milliseconds
  pub window: u64,
  pub step:   u64,
  pub oracle: Option<HashMap<u64, u32>>,
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTPParams {
  pub start:   u64,
  pub hash:    HashAlgorithm,
  pub digits:  u8,
  pub step:    u64,
  pub window:  u64,
  pub pad:     String,
  pub offsets: String,
}

impl Default for TOTPOptions {
  fn default() -> Self {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

    Self {
      id:     Some("totp".to_string()),
      secret: None,
      digits: 6,
      hash:   HashAlgorithm::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "mfkdf.com".to_string(),
      time:   Some(now_ms),
      window: 87600,
      step:   30,
      oracle: None,
    }
  }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTP {
  pub options: TOTPOptions,
  pub params:  Value,
  pub code:    u32,
  pub target:  u32,
}

fn mod_positive(n: i64, m: i64) -> i64 { ((n % m) + m) % m }

impl FactorMetadata for TOTP {
  fn kind(&self) -> String { "totp".to_string() }

  fn bytes(&self) -> Vec<u8> { self.target.to_be_bytes().to_vec() }
}

impl FactorSetup for TOTP {
  type Output = Value;
  type Params = Value;

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    let time =
      self.options.time.ok_or(MFKDF2Error::MissingSetupParams("time".to_string()))? as u128;
    let mut offsets = Vec::with_capacity((4 * self.options.window) as usize);
    let padded_secret =
      self.options.secret.as_ref().ok_or(MFKDF2Error::MissingSetupParams("secret".to_string()))?;

    for i in 0..self.options.window {
      // Calculate the time-step 'T' as per RFC 6238, Section 4.2.
      // T = floor((CurrentUnixTime - T0) / X)
      // Here, T0 is 0 (Unix epoch) and X is self.options.step.
      // We add 'i' to generate a window of future OTPs for offline use.
      let counter = (time / 1000) as u64 / self.options.step + i;
      let code =
        generate_hotp_code(&padded_secret[..20], counter, &self.options.hash, self.options.digits);

      let mut offset =
        mod_positive(self.target as i64 - code as i64, 10_i64.pow(self.options.digits as u32))
          as u32;

      let oracle_time = counter * self.options.step * 1000;
      if self.options.oracle.is_some()
        && self.options.oracle.as_ref().unwrap().contains_key(&oracle_time)
      {
        offset = mod_positive(
          offset as i64 + *self.options.oracle.as_ref().unwrap().get(&oracle_time).unwrap() as i64,
          10_i64.pow(self.options.digits as u32),
        ) as u32;
      }

      offsets.extend_from_slice(&offset.to_be_bytes());
    }

    let pad = encrypt(padded_secret, &key.0);

    let params = TOTPParams {
      start:   time as u64,
      hash:    self.options.hash.clone(),
      digits:  self.options.digits,
      step:    self.options.step,
      window:  self.options.window,
      pad:     base64::prelude::BASE64_STANDARD.encode(&pad),
      offsets: base64::prelude::BASE64_STANDARD.encode(&offsets),
    };

    Ok(serde_json::to_value(params)?)
  }

  fn output(&self) -> Self::Output {
    json!({
      "scheme": "otpauth",
      "type": "totp",
      "label": self.options.label,
      "secret": &self.options.secret.as_ref().unwrap()[..20],
      "issuer": self.options.issuer,
      "algorithm": self.options.hash.to_string(),
      "digits": self.options.digits,
      "period": self.options.step,
      "uri": otpauth::otpauth_url(&OtpauthUrlOptions {
        secret: hex::encode(&self.options.secret.as_ref().unwrap()[..20]),
        label: self.options.label.clone(),
        kind: Some(otpauth::Kind::Totp),
        counter: None,
        issuer: Some(self.options.issuer.clone()),
        digits: Some(self.options.digits),
        period: Some(self.options.step),
        shared: Some(otpauth::SharedOptions {
          encoding: Some(otpauth::Encoding::Hex),
          algorithm: Some(self.options.hash.clone()),
        }),
      }).unwrap()
    })
  }
}

pub fn totp(options: TOTPOptions) -> MFKDF2Result<MFKDF2Factor> {
  let mut options = options;

  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let id = options.id.clone().unwrap_or("totp".to_string());
  if options.digits < 6 || options.digits > 8 {
    return Err(crate::error::MFKDF2Error::InvalidTOTPDigits);
  }

  // secret length validation
  if let Some(ref secret) = options.secret
    && secret.len() != 20
  {
    return Err(crate::error::MFKDF2Error::InvalidSecretLength(id));
  }

  let secret = options.secret.unwrap_or_else(|| {
    let mut secret = [0u8; 20];
    crate::rng::fill_bytes(&mut secret);
    secret.to_vec()
  });

  if options.time.is_none() {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    options.time = Some(now_ms);
  }

  // Generate random target
  let target = crate::rng::gen_range_u32(10_u32.pow(u32::from(options.digits)) - 1);

  let mut secret_pad = [0u8; 12];
  crate::rng::fill_bytes(&mut secret_pad);
  let padded_secret = secret.into_iter().chain(secret_pad.into_iter()).collect();
  options.secret = Some(padded_secret);

  let entropy = Some(options.digits as f64 * 10.0_f64.log2());

  Ok(MFKDF2Factor {
    id: Some(id),
    factor_type: FactorType::TOTP(TOTP { options, params: Value::Null, code: 0, target }),
    entropy,
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn setup_totp(options: TOTPOptions) -> MFKDF2Result<MFKDF2Factor> { totp(options) }

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{crypto::decrypt, error::MFKDF2Error};

  fn mock_construction() -> MFKDF2Factor {
    let options = TOTPOptions {
      id: Some("test".to_string()),
      digits: 8,
      secret: Some(b"my-super-secret-1234".to_vec()), // 31 bytes
      time: Some(1672531200000),                      // 2023-01-01 00:00:00 UTC in milliseconds
      ..Default::default()
    };

    let result = totp(options);
    assert!(result.is_ok());

    result.unwrap()
  }

  #[test]
  fn construction() {
    let options = TOTPOptions {
      id: Some("test".to_string()),
      digits: 8,
      hash: HashAlgorithm::Sha256,
      issuer: "TestCorp".to_string(),
      label: "tester@testcorp.com".to_string(),
      ..Default::default()
    };

    let result = totp(options);
    assert!(result.is_ok());

    let factor = result.unwrap();
    assert_eq!(factor.id, Some("test".to_string()));
    // assert_eq!(factor.salt.len(), 32);

    assert!(matches!(factor.factor_type, FactorType::TOTP(_)));
    if let FactorType::TOTP(totp_factor) = factor.factor_type {
      assert_eq!(totp_factor.options.digits, 8);
      assert_eq!(totp_factor.options.hash, HashAlgorithm::Sha256);
      assert_eq!(totp_factor.options.issuer, "TestCorp".to_string());
      assert_eq!(totp_factor.options.label, "tester@testcorp.com".to_string());
      assert!(totp_factor.options.secret.is_some());
      assert_eq!(totp_factor.options.secret.as_ref().unwrap().len(), 32); // 20 bytes generated + 12 bytes padding
      assert!(totp_factor.target < 10_u32.pow(8));
    }
  }

  #[test]
  fn empty_id() {
    let options = TOTPOptions { id: Some("".to_string()), ..Default::default() };
    let result = totp(options);
    assert!(matches!(result, Err(MFKDF2Error::MissingFactorId)));
  }

  #[test]
  fn invalid_digits_too_low() {
    let options = TOTPOptions { digits: 5, ..Default::default() };
    let result = totp(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidTOTPDigits)));
  }

  #[test]
  fn invalid_digits_too_high() {
    let options = TOTPOptions { digits: 9, ..Default::default() };
    let result = totp(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidTOTPDigits)));
  }

  #[test]
  fn invalid_secret_length() {
    let options = TOTPOptions {
      secret: Some(b"my-secret-is-super-secret-123456".to_vec()),
      ..Default::default()
    };
    let result = totp(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidSecretLength(_))));
  }

  #[test]
  fn secret_generation() {
    let options = TOTPOptions { secret: None, ..Default::default() };
    let result = totp(options);
    assert!(result.is_ok());
    let factor = result.unwrap();
    if let FactorType::TOTP(totp_factor) = factor.factor_type {
      assert!(totp_factor.options.secret.is_some());
      // 20 bytes generated + 12 bytes padding
      assert_eq!(totp_factor.options.secret.as_ref().unwrap().len(), 32);
    } else {
      panic!("Wrong factor type");
    }
  }

  #[test]
  fn params_setup() {
    let factor = mock_construction();
    let key = [0u8; 32];

    let totp_factor = match factor.factor_type {
      FactorType::TOTP(ref f) => f,
      _ => panic!("Factor type should be TOTP"),
    };

    let params = totp_factor.params(key.into());
    assert!(params.is_ok());
    let params = params.unwrap();
    assert!(params.is_object());

    assert_eq!(params["start"], 1672531200000_u64);
    assert_eq!(params["hash"], "sha1");
    assert_eq!(params["digits"], 8);
    assert_eq!(params["step"], 30);
    assert_eq!(params["window"], 87600);

    let pad_b64 = params["pad"].as_str().unwrap();
    let pad = base64::prelude::BASE64_STANDARD.decode(pad_b64).unwrap();
    let decrypted_secret = decrypt(pad, &key);
    let original_secret = totp_factor.options.secret.as_ref().unwrap();
    assert_eq!(&decrypted_secret[..original_secret.len()], original_secret.as_slice());

    let offsets_b64 = params["offsets"].as_str().unwrap();
    let offsets = base64::prelude::BASE64_STANDARD.decode(offsets_b64).unwrap();
    assert_eq!(offsets.len(), 4 * 87600);
  }

  #[test]
  fn output_setup() {
    let factor = mock_construction();

    let totp_factor = match factor.factor_type {
      FactorType::TOTP(ref f) => f,
      _ => panic!("Factor type should be TOTP"),
    };

    let output = totp_factor.output();
    assert!(output.is_object());

    assert_eq!(output["scheme"], "otpauth");
    assert_eq!(output["type"], "totp");
    assert_eq!(output["label"], "mfkdf.com");
    assert_eq!(output["issuer"], "MFKDF");
    assert_eq!(output["algorithm"], "sha1");
    assert_eq!(output["digits"], 8);
    assert_eq!(output["period"], 30);

    let secret = output["secret"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_u64().unwrap() as u8)
      .collect::<Vec<u8>>();
    assert_eq!(secret.len(), 20);
    assert_eq!(secret, &totp_factor.options.secret.as_ref().unwrap()[..20]);
  }

  #[test]
  fn bytes() {
    let factor = mock_construction();
    let totp_factor = match factor.factor_type {
      FactorType::TOTP(ref f) => f,
      _ => panic!("Factor type should be TOTP"),
    };

    let bytes = totp_factor.bytes();
    let expected_bytes = totp_factor.target.to_be_bytes();
    assert_eq!(bytes, expected_bytes);
  }
}
