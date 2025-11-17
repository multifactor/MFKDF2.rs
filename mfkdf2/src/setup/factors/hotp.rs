use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  crypto::encrypt,
  definitions::{FactorMetadata, FactorType, Key, MFKDF2Factor},
  error::MFKDF2Result,
  otpauth::{self, HashAlgorithm, OtpauthUrlOptions, generate_hotp_code},
  setup::FactorSetup,
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTPOptions {
  pub id:     Option<String>,
  // TODO (@lonerapier): use trait based type update for secret
  // Initially this should be 20 bytes, that later gets padded to 32 during construction.
  pub secret: Option<Vec<u8>>,
  pub digits: u8,
  pub hash:   HashAlgorithm,
  pub issuer: String,
  pub label:  String,
}

impl Default for HOTPOptions {
  fn default() -> Self {
    Self {
      id:     Some("hotp".to_string()),
      secret: None,
      digits: 6,
      hash:   HashAlgorithm::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "mfkdf.com".to_string(),
    }
  }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTP {
  // TODO (sambhav): is it safe to add options in the factor struct here?
  pub options: HOTPOptions,
  pub params:  Value,
  pub code:    u32,
  pub target:  u32,
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTPParams {
  pub hash:    HashAlgorithm,
  pub digits:  u8,
  pub pad:     String,
  pub counter: u64,
  pub offset:  u32,
}

impl FactorMetadata for HOTP {
  fn kind(&self) -> String { "hotp".to_string() }

  fn bytes(&self) -> Vec<u8> { self.target.to_be_bytes().to_vec() }
}

impl FactorSetup for HOTP {
  type Output = Value;
  type Params = Value;

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    // Generate or use provided secret
    let padded_secret = if let Some(secret) = self.options.secret.clone() {
      secret
    } else {
      let mut secret = [0u8; 32]; // Default to 32 bytes
      crate::rng::fill_bytes(&mut secret);
      secret.to_vec()
    };

    // Generate HOTP code with counter = 1
    let code = generate_hotp_code(&padded_secret[..20], 1, &self.options.hash, self.options.digits);

    // Calculate offset
    let offset =
      mod_positive(self.target as i64 - code as i64, 10_i64.pow(self.options.digits as u32)) as u32;

    let pad = encrypt(&padded_secret, &key.0);

    let params = HOTPParams {
      hash: self.options.hash.clone(),
      digits: self.options.digits,
      pad: base64::prelude::BASE64_STANDARD.encode(&pad),
      counter: 1,
      offset,
    };

    Ok(serde_json::to_value(params)?)
  }

  fn output(&self) -> Self::Output {
    json!({
      "scheme": "otpauth",
      "type": "hotp",
      "label": self.options.label,
      "secret": &self.options.secret.as_ref().unwrap()[..20],
      "issuer": self.options.issuer,
      "algorithm": self.options.hash.to_string(),
      "digits": self.options.digits,
      "counter": 1,
      "uri": otpauth::otpauth_url(&OtpauthUrlOptions {
        secret: hex::encode(&self.options.secret.as_ref().unwrap()[..20]),
        label: self.options.label.clone(),
        kind: Some(otpauth::Kind::Hotp),
        counter: Some(1),
        issuer: Some(self.options.issuer.clone()),
        digits: Some(self.options.digits),
        period: None,
        shared: Some(otpauth::SharedOptions {
          encoding: Some(otpauth::Encoding::Hex),
          algorithm: Some(self.options.hash.clone()),
        }),
      }).unwrap()
    })
  }
}

#[inline]
pub fn mod_positive(n: i64, m: i64) -> i64 { ((n % m) + m) % m }

pub fn hotp(options: HOTPOptions) -> MFKDF2Result<MFKDF2Factor> {
  let mut options = options;

  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let id = options.id.clone().unwrap_or("hotp".to_string());

  if options.digits < 6 || options.digits > 8 {
    return Err(crate::error::MFKDF2Error::InvalidHOTPDigits);
  }

  // TODO (@lonerapier); remove this validation later using static secret type
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

  // Generate random target
  let target = crate::rng::gen_range_u32(10_u32.pow(u32::from(options.digits)) - 1);

  // Pad secret to 32 bytes
  let mut secret_pad = [0u8; 12];
  crate::rng::fill_bytes(&mut secret_pad);
  let padded_secret = secret.iter().chain(secret_pad.iter()).cloned().collect::<Vec<u8>>();
  options.secret = Some(padded_secret);

  let entropy = Some(options.digits as f64 * 10.0_f64.log2());

  // TODO (autoparallel): Code should possibly be an option, though this follows the same pattern as
  // the password factor which stores the actual password in the struct.
  Ok(MFKDF2Factor {
    id: Some(id),
    factor_type: FactorType::HOTP(HOTP { options, params: Value::Null, code: 0, target }),
    entropy,
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn setup_hotp(options: HOTPOptions) -> MFKDF2Result<MFKDF2Factor> { hotp(options) }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hotp_setup_with_known_secret() {
    let key = [0u8; 32];
    let options = HOTPOptions {
      id:     Some("test_hotp".to_string()),
      secret: Some(b"hello world mfkdf2!!".to_vec()),
      digits: 6,
      hash:   HashAlgorithm::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    };

    let factor = hotp(options).unwrap();
    assert_eq!(factor.kind(), "hotp");
    assert_eq!(factor.id, Some("test_hotp".to_string()));
    assert_eq!(factor.data().len(), 4); // u32 target as bytes

    // Test that params can be generated
    let params = factor.factor_type.setup().params(key.into()).unwrap();
    assert!(params.is_object());

    assert!(params["hash"].is_string());
    assert!(params["digits"].is_number());
    assert!(params["pad"].is_string());
    assert!(params["counter"].is_number());
    assert!(params["offset"].is_number());
  }

  #[test]
  fn hotp_setup_default_options() {
    let key = [0u8; 32];
    let options = HOTPOptions::default();
    let factor = hotp(options).unwrap();

    assert_eq!(factor.kind(), "hotp");
    assert_eq!(factor.id, Some("hotp".to_string()));
    assert_eq!(factor.data().len(), 4);
    assert!(factor.entropy.is_some());
    let params = factor.factor_type.setup().params(key.into()).unwrap();
    assert!(params.is_object());

    let output = factor.factor_type.output();
    assert!(output.is_object());
  }

  #[test]
  fn hotp_validation() {
    // Test empty id, corresponds to JS test 'id/range'
    let options = HOTPOptions { id: Some("".to_string()), ..Default::default() };
    let result = hotp(options);
    assert!(matches!(result, Err(crate::error::MFKDF2Error::MissingFactorId)));

    // Test invalid digits, corresponds to JS tests 'digits/low' and 'digits/high'
    // Lower bound
    let options_low = HOTPOptions {
      digits: 5, // Too small
      ..Default::default()
    };
    let result_low = hotp(options_low);
    assert!(matches!(result_low, Err(crate::error::MFKDF2Error::InvalidHOTPDigits)));

    let options_4 = HOTPOptions {
      digits: 4, // Too small
      ..Default::default()
    };
    let result_4 = hotp(options_4);
    assert!(matches!(result_4, Err(crate::error::MFKDF2Error::InvalidHOTPDigits)));

    // Upper bound
    let options_high = HOTPOptions {
      digits: 9, // Too large
      ..Default::default()
    };
    let result_high = hotp(options_high);
    assert!(matches!(result_high, Err(crate::error::MFKDF2Error::InvalidHOTPDigits)));
  }

  #[test]
  fn test_hotp_setup() {
    let options = HOTPOptions {
      id:     Some("hotp".to_string()),
      secret: Some(b"hello world mfkdf2!!".to_vec()),
      digits: 6,
      hash:   HashAlgorithm::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    };

    let material = hotp(options).unwrap();
    assert_eq!(material.kind(), "hotp");
    assert_eq!(material.id, Some("hotp".to_string()));
    assert_eq!(material.data().len(), 4); // u32 target
  }

  #[test]
  fn params_setup_pad_decryption() {
    let key = [0u8; 32];
    let secret = b"my-secret-password-1".to_vec();
    let options = HOTPOptions { secret: Some(secret), ..Default::default() };

    let factor = hotp(options).unwrap();
    let hotp_factor = match factor.factor_type {
      FactorType::HOTP(h) => h,
      _ => panic!("Wrong factor type"),
    };

    let original_padded_secret = hotp_factor.options.secret.as_ref().unwrap();

    let params = hotp_factor.params(key.into()).unwrap();
    assert!(params.is_object());

    let pad_b64 = params["pad"].as_str().unwrap();
    let pad = BASE64_STANDARD.decode(pad_b64).unwrap();

    let decrypted_secret = crate::crypto::decrypt(pad, &key);

    assert_eq!(&decrypted_secret[..original_padded_secret.len()], &original_padded_secret[..]);
  }

  #[test]
  fn params_setup_offset_calculation() {
    let key = [0u8; 32];
    let secret = b"my-secret-password-2".to_vec();
    let options = HOTPOptions { secret: Some(secret), ..Default::default() };

    let factor = hotp(options).unwrap();
    let hotp_factor = match factor.factor_type {
      FactorType::HOTP(h) => h,
      _ => panic!("Wrong factor type"),
    };

    let params = hotp_factor.params(key.into()).unwrap();
    assert!(params.is_object());

    let offset = params["offset"].as_u64().unwrap() as u32;

    let padded_secret = hotp_factor.options.secret.as_ref().unwrap();
    let code = generate_hotp_code(
      &padded_secret[..20],
      1,
      &hotp_factor.options.hash,
      hotp_factor.options.digits,
    );

    let expected_offset = mod_positive(
      hotp_factor.target as i64 - code as i64,
      10_i64.pow(hotp_factor.options.digits as u32),
    ) as u32;

    assert_eq!(offset, expected_offset);
  }

  #[test]
  fn empty_id() {
    let options = HOTPOptions { id: Some("".to_string()), ..Default::default() };
    let result = hotp(options);
    assert!(matches!(result, Err(crate::error::MFKDF2Error::MissingFactorId)));
  }

  #[test]
  fn invalid_digits_too_low() {
    let options = HOTPOptions { digits: 5, ..Default::default() };
    let result = hotp(options);
    assert!(matches!(result, Err(crate::error::MFKDF2Error::InvalidHOTPDigits)));
  }

  #[test]
  fn invalid_digits_too_high() {
    let options = HOTPOptions { digits: 9, ..Default::default() };
    let result = hotp(options);
    assert!(matches!(result, Err(crate::error::MFKDF2Error::InvalidHOTPDigits)));
  }

  #[test]
  fn invalid_secret_length() {
    let options = HOTPOptions {
      secret: Some(b"my-secret-is-super-secret-123456".to_vec()),
      ..Default::default()
    };
    let result = hotp(options);
    assert!(matches!(result, Err(crate::error::MFKDF2Error::InvalidSecretLength(_))));
  }
}
