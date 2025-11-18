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
  setup::{FactorSetup, factors::hotp::mod_positive},
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTPOptions {
  pub id:     Option<String>,
  pub secret: Option<Vec<u8>>,
  pub digits: Option<u32>,
  pub hash:   Option<HashAlgorithm>,
  pub issuer: Option<String>,
  pub label:  Option<String>,
  pub time:   Option<u64>, // Unix epoch time in milliseconds
  pub window: Option<u64>,
  pub step:   Option<u64>,
  pub oracle: Option<HashMap<u64, u32>>,
}

impl Default for TOTPOptions {
  fn default() -> Self {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

    Self {
      id:     Some("totp".to_string()),
      secret: None,
      digits: Some(6),
      hash:   Some(HashAlgorithm::Sha1),
      issuer: Some("MFKDF".to_string()),
      label:  Some("mfkdf.com".to_string()),
      time:   Some(now_ms), // TODO: see if this can be None
      window: Some(87600),
      step:   Some(30),
      oracle: None,
    }
  }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTPConfig {
  pub id:     String,
  pub secret: Vec<u8>,
  pub digits: u32,
  pub hash:   HashAlgorithm,
  pub issuer: String,
  pub label:  String,
  pub time:   u64,
  pub window: u64,
  pub step:   u64,
  pub oracle: Option<HashMap<u64, u32>>,
}

impl TryFrom<TOTPOptions> for TOTPConfig {
  type Error = MFKDF2Error;

  fn try_from(value: TOTPOptions) -> Result<Self, Self::Error> {
    Ok(TOTPConfig {
      id:     value.id.ok_or(MFKDF2Error::MissingFactorId)?,
      secret: value.secret.ok_or(MFKDF2Error::MissingSetupParams("secret".to_string()))?,
      digits: value.digits.ok_or(MFKDF2Error::InvalidTOTPDigits)?,
      hash:   value.hash.unwrap_or(HashAlgorithm::Sha1),
      issuer: value.issuer.unwrap_or("MFKDF".to_string()),
      label:  value.label.unwrap_or("mfkdf.com".to_string()),
      time:   value.time.ok_or(MFKDF2Error::MissingSetupParams("time".to_string()))?,
      window: value.window.unwrap_or(87600),
      step:   value.step.unwrap_or(30),
      oracle: value.oracle,
    })
  }
}

impl Default for TOTPConfig {
  fn default() -> Self {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

    Self {
      id:     "totp".to_string(),
      secret: [0u8; 20].to_vec(),
      digits: 6,
      hash:   HashAlgorithm::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "mfkdf.com".to_string(),
      time:   now_ms,
      window: 87600,
      step:   30,
      oracle: None,
    }
  }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTPParams {
  pub start:   u64,
  pub hash:    HashAlgorithm,
  pub digits:  u32,
  pub step:    u64,
  pub window:  u64,
  pub pad:     String,
  pub offsets: String,
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTP {
  pub config: TOTPConfig,
  pub params: Value,
  pub code:   u32,
  pub target: u32,
}

impl FactorMetadata for TOTP {
  fn kind(&self) -> String { "totp".to_string() }

  fn bytes(&self) -> Vec<u8> { self.target.to_be_bytes().to_vec() }
}

impl FactorSetup for TOTP {
  type Output = Value;
  type Params = Value;

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    let time = u128::from(self.config.time);
    let mut offsets = Vec::with_capacity(4 * self.config.window as usize);

    for i in 0..self.config.window {
      // Calculate the time-step 'T' as per RFC 6238, Section 4.2.
      // T = floor((CurrentUnixTime - T0) / X)
      // Here, T0 is 0 (Unix epoch) and X is self.config.step.
      // We add 'i' to generate a window of future OTPs for offline use.
      let counter = (time / 1000) as u64 / self.config.step + i;
      let code = generate_hotp_code(
        &self.config.secret[..20],
        counter,
        &self.config.hash,
        self.config.digits,
      );

      let mut offset = mod_positive(
        i64::from(self.target) - i64::from(code),
        10_i64.pow(u32::from(self.config.digits)),
      );

      let oracle_time = counter * self.config.step * 1000;
      if self.config.oracle.is_some()
        && self.config.oracle.as_ref().unwrap().contains_key(&oracle_time)
      {
        offset = mod_positive(
          i64::from(offset)
            + i64::from(*self.config.oracle.as_ref().unwrap().get(&oracle_time).unwrap()),
          10_i64.pow(u32::from(self.config.digits)),
        );
      }

      offsets.extend_from_slice(&offset.to_be_bytes());
    }

    let pad = encrypt(&self.config.secret, &key.0);

    let params = TOTPParams {
      start:   time as u64,
      hash:    self.config.hash.clone(),
      digits:  self.config.digits,
      step:    self.config.step,
      window:  self.config.window,
      pad:     base64::prelude::BASE64_STANDARD.encode(&pad),
      offsets: base64::prelude::BASE64_STANDARD.encode(&offsets),
    };

    Ok(serde_json::to_value(params)?)
  }

  fn output(&self) -> Self::Output {
    json!({
      "scheme": "otpauth",
      "type": "totp",
        "label": self.config.label,
      "secret": &self.config.secret[..20],
      "issuer": self.config.issuer,
      "algorithm": self.config.hash.to_string(),
      "digits": self.config.digits,
      "period": self.config.step,
      "uri": otpauth::otpauth_url(&OtpauthUrlOptions {
        secret: hex::encode(&self.config.secret[..20]),
        label: self.config.label.clone(),
        kind: Some(otpauth::Kind::Totp),
        counter: None,
        issuer: Some(self.config.issuer.clone()),
        digits: Some(self.config.digits),
        period: Some(self.config.step),
        shared: Some(otpauth::SharedOptions {
          encoding: Some(otpauth::Encoding::Hex),
          algorithm: Some(self.config.hash.clone()),
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

  if let Some(digits) = options.digits
    && (digits < 6 || digits > 8)
  {
    return Err(crate::error::MFKDF2Error::InvalidTOTPDigits);
  }
  options.digits = Some(options.digits.unwrap_or(6));

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
  let target = crate::rng::gen_range_u32(10_u32.pow(u32::from(options.digits.unwrap())) - 1);

  let mut secret_pad = [0u8; 12];
  crate::rng::fill_bytes(&mut secret_pad);
  let padded_secret = secret.into_iter().chain(secret_pad).collect();
  options.secret = Some(padded_secret);

  let entropy = Some(f64::from(options.digits.unwrap()) * 10.0_f64.log2());

  options.id = Some(id.clone());

  Ok(MFKDF2Factor {
    id: Some(id),
    factor_type: FactorType::TOTP(TOTP {
      config: options.try_into()?,
      params: Value::Null,
      code: 0,
      target,
    }),
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
      digits: Some(8),
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
      digits: Some(8),
      hash: Some(HashAlgorithm::Sha256),
      issuer: Some("TestCorp".to_string()),
      label: Some("tester@testcorp.com".to_string()),
      ..Default::default()
    };

    let result = totp(options);
    assert!(result.is_ok());

    let factor = result.unwrap();
    assert_eq!(factor.id, Some("test".to_string()));
    // assert_eq!(factor.salt.len(), 32);

    assert!(matches!(factor.factor_type, FactorType::TOTP(_)));
    if let FactorType::TOTP(totp_factor) = factor.factor_type {
      assert_eq!(totp_factor.config.digits, 8);
      assert_eq!(totp_factor.config.hash, HashAlgorithm::Sha256);
      assert_eq!(totp_factor.config.issuer, "TestCorp".to_string());
      assert_eq!(totp_factor.config.label, "tester@testcorp.com".to_string());
      assert_eq!(totp_factor.config.secret.len(), 32); // 20 bytes generated + 12 bytes padding
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
    let options = TOTPOptions { digits: Some(5), ..Default::default() };
    let result = totp(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidTOTPDigits)));
  }

  #[test]
  fn invalid_digits_too_high() {
    let options = TOTPOptions { digits: Some(9), ..Default::default() };
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
      // 20 bytes generated + 12 bytes padding
      assert_eq!(totp_factor.config.secret.len(), 32);
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
    let original_secret = totp_factor.config.secret.as_slice();
    assert_eq!(&decrypted_secret[..original_secret.len()], original_secret);

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
    assert_eq!(secret, totp_factor.config.secret[..20]);
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
