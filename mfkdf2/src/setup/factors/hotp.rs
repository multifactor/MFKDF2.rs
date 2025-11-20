//! Counter-based HOTP factor setup.
//!
//! This factor models a standard OATH HOTP "soft token" (e.g. Google Authenticator, 1Password, or
//! any RFC 4226 implementation) and the matching server-side verification logic.
//!
//! Conceptually:
//! - An authenticator app holds a shared HOTP key `hotkeyₜ` and counter `ctrₜ`. On each use it
//!   displays a one-time code `otpₜ,ᵢ` that both client and server can compute given (hotkeyₜ,
//!   ctrₜ,ᵢ).
//! - MFKDF2 needs a *fixed* piece of factor material σₜ rather than a changing OTP. For HOTP, each
//!   dynamic code Wₜ,ᵢ = otpₜ,ᵢ is converted into a fixed secret integer `targetₜ` in the range [0,
//!   10ᵈ), where `d` is the number of digits in the code.
//!
//! During **setup**:
//! - sample a random integer `targetₜ` in [0, 10ᵈ)
//! - compute the first HOTP code `otpₜ,₀` using `hotkeyₜ` and counter ctrₜ,₀ = 1
//! - store an offset offsetₜ,₀ = (targetₜ - otpₜ,₀) % 10ᵈ
//! - encrypt the padded HOTP secret under the final derived key `K` and expose it as the `"pad"`
//!   field in the public params.
//!
//! The public HOTP parameters βₜ produced here (digits `d`, initial `counter`, `offset`, and the
//! encrypted `pad`) are what get embedded into the MFKDF2 policy. On the derive side, the client
//! sends a fresh HOTP code Wₜ,ᵢ = otpₜ,ᵢ, and the library reconstructs the same targetₜ using the
//! stored offset and counter, giving you stable factor material that is backward-compatible with
//! existing software tokens.
//!
//! Software-token based key-derivation constructions require no changes to existing authenticator
//! applications like Google Authenticator. Because the HOTP key hotkeyₜ is stored inside the factor
//! state βₜ (encrypted as the pad), the computation of new offset values happens entirely inside
//! the library's setup/derive machinery. The authenticator app is only ever asked to display otpₜ,ᵢ
//! once per login, exactly as it does today; it does not participate directly in the key-derivation
//! logic.
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  crypto::encrypt,
  definitions::{FactorMetadata, FactorType, Key, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  otpauth::{self, HashAlgorithm, OtpAuthUrlOptions, generate_otp_token},
  setup::FactorSetup,
};

/// Options for configuring a HOTP factor before setup
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTPOptions {
  /// Optional application-defined identifier for the factor. Defaults to `"hotp"`. If
  /// provided, it must be non-empty
  pub id:     Option<String>,
  // TODO (@lonerapier): use trait based type update for secret
  // Initially this should be 20 bytes, that later gets padded to 32 during construction.
  /// 20‑byte HOTP secret. If omitted, a random secret is generated
  pub secret: Option<Vec<u8>>,
  /// Number of digits in the OTP code (6–8). Values outside this range cause
  /// [`MFKDF2Error::InvalidHOTPDigits`]
  pub digits: Option<u32>,
  /// Hash algorithm used by the HOTP generator (default: SHA‑1)
  pub hash:   Option<HashAlgorithm>,
  /// A string value indicating the provider or service the credential is associated with.
  pub issuer: Option<String>,
  /// A string value identifying which account a credential is associated with. It also serves
  /// as the unique identifier for the credential itself.
  pub label:  Option<String>,
}

impl Default for HOTPOptions {
  fn default() -> Self {
    Self {
      id:     Some("hotp".to_string()),
      secret: None,
      digits: Some(6),
      hash:   Some(HashAlgorithm::Sha1),
      issuer: Some("MFKDF".to_string()),
      label:  Some("mfkdf.com".to_string()),
    }
  }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTPConfig {
  pub id:     String,
  pub secret: Vec<u8>,
  pub digits: u32,
  pub hash:   HashAlgorithm,
  pub issuer: String,
  pub label:  String,
}

impl TryFrom<HOTPOptions> for HOTPConfig {
  type Error = MFKDF2Error;

  fn try_from(value: HOTPOptions) -> Result<Self, Self::Error> {
    Ok(HOTPConfig {
      id:     value.id.ok_or(MFKDF2Error::MissingFactorId)?,
      secret: value.secret.ok_or(MFKDF2Error::MissingSetupParams("secret".to_string()))?,
      digits: value.digits.ok_or(MFKDF2Error::InvalidHOTPDigits)?,
      hash:   value.hash.unwrap_or(HashAlgorithm::Sha1),
      issuer: value.issuer.unwrap_or("MFKDF".to_string()),
      label:  value.label.unwrap_or("mfkdf.com".to_string()),
    })
  }
}

impl Default for HOTPConfig {
  fn default() -> Self {
    Self {
      id:     "hotp".to_string(),
      secret: [0u8; 20].to_vec(),
      digits: 6,
      hash:   HashAlgorithm::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "mfkdf.com".to_string(),
    }
  }
}

/// HOTP factor state.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTP {
  // TODO (@lonerapier): config is only used for setup, not for derive
  /// HOTP configuration.
  pub config: HOTPConfig,
  /// HOTP public parameters.
  pub params: Value,
  /// HOTP code.
  pub code:   u32,
  /// HOTP factor material. The target code that is used to derive the key.
  pub target: u32,
}

/// HOTP public parameters.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTPParams {
  /// Hash algorithm used by the HOTP generator.
  pub hash:    HashAlgorithm,
  /// Number of digits in the OTP code.
  pub digits:  u32,
  /// Base64 encoded pad.
  pub pad:     String,
  /// HOTP counter.
  pub counter: u64,
  /// Target - code offset.
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
    // Generate HOTP code with counter = 1
    let code =
      generate_otp_token(&self.config.secret[..20], 1, &self.config.hash, self.config.digits);

    // Calculate offset
    let offset =
      mod_positive(i64::from(self.target) - i64::from(code), 10_i64.pow(self.config.digits));

    let pad = encrypt(&self.config.secret, &key.0);

    let params = HOTPParams {
      hash: self.config.hash.clone(),
      digits: self.config.digits,
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
      "label": self.config.label,
      "secret": &self.config.secret[..20],
      "issuer": self.config.issuer,
      "algorithm": self.config.hash.to_string(),
      "digits": self.config.digits,
      "counter": 1,
      "uri": otpauth::otpauth_url(&OtpAuthUrlOptions {
        secret: hex::encode(&self.config.secret[..20]),
        label: self.config.label.clone(),
        kind: Some(otpauth::Kind::Hotp),
        counter: Some(1),
        issuer: Some(self.config.issuer.clone()),
        digits: Some(self.config.digits),
        period: None,
        encoding: Some(otpauth::Encoding::Hex),
        algorithm: Some(self.config.hash.clone()),
      }).unwrap()
    })
  }
}

#[inline]
#[must_use]
pub fn mod_positive(n: i64, m: i64) -> u32 { (((n % m) + m) % m) as u32 }

/// Initializes an HOTP factor from the given options.
///
/// Validates the configuration, generates a random target code and (optionally) secret, and returns
/// an [`MFKDF2Factor`] that can participate in MFKDF2 key setup. The factor's `output()` method
/// exposes an `otpauth://` URI that you can display as a QR code for users.
///
/// # Errors
///
/// - [`MFKDF2Error::MissingFactorId`] if `id` is provided but empty.
/// - [`MFKDF2Error::InvalidHOTPDigits`] if `digits` is set outside `6..=8`.
/// - [`MFKDF2Error::InvalidSecretLength`] if `secret` is provided but not exactly 20 bytes.
///
/// # Example
///
/// Pairing with an authenticator app using a known secret:
///
/// ```rust
/// # use mfkdf2::setup::factors::hotp::{hotp, HOTPOptions};
/// # use mfkdf2::otpauth::HashAlgorithm;
/// # use mfkdf2::setup::FactorSetup;
///
/// let options = HOTPOptions {
///   id:     Some("login-hotp".into()),
///   secret: Some(b"shared-hotp-secret!!".to_vec()), // 20 bytes
///   digits: Some(6),
///   hash:   Some(HashAlgorithm::Sha1),
///   issuer: Some("ExampleApp".into()),
///   label:  Some("user@example.com".into()),
/// };
/// let factor = hotp(options)?;
/// let output = factor.factor_type.output();
/// assert_eq!(output["type"], "hotp");
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// Invalid digits
///
/// ```rust
/// # use mfkdf2::setup::factors::hotp::{hotp, HOTPOptions};
/// # use mfkdf2::otpauth::HashAlgorithm;
/// # use mfkdf2::setup::FactorSetup;
///
/// let options = HOTPOptions { digits: Some(4), ..Default::default() };
/// let result = hotp(options);
/// assert!(matches!(result, Err(mfkdf2::error::MFKDF2Error::InvalidHOTPDigits)));
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn hotp(options: HOTPOptions) -> MFKDF2Result<MFKDF2Factor> {
  let mut options = options;

  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let id = options.id.clone().unwrap_or("hotp".to_string());

  if let Some(digits) = options.digits
    && !(6..=8).contains(&digits)
  {
    return Err(crate::error::MFKDF2Error::InvalidHOTPDigits);
  }
  options.digits = Some(options.digits.unwrap_or(6));

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
  let target = crate::rng::gen_range_u32(10_u32.pow(options.digits.unwrap()) - 1);

  // Pad secret to 32 bytes
  let mut secret_pad = [0u8; 12];
  crate::rng::fill_bytes(&mut secret_pad);
  let padded_secret = secret.into_iter().chain(secret_pad).collect();
  options.secret = Some(padded_secret);

  let entropy = Some(f64::from(options.digits.unwrap()) * 10.0_f64.log2());

  options.id = Some(id.clone());

  // TODO (autoparallel): Code should possibly be an option, though this follows the same pattern as
  // the password factor which stores the actual password in the struct.
  Ok(MFKDF2Factor {
    id: Some(id),
    factor_type: FactorType::HOTP(HOTP {
      config: options.try_into()?,
      params: Value::Null,
      code: 0,
      target,
    }),
    entropy,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn setup_hotp(options: HOTPOptions) -> MFKDF2Result<MFKDF2Factor> { hotp(options) }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hotp_setup_with_known_secret() {
    let key = [0u8; 32];
    let options = HOTPOptions {
      id: Some("test_hotp".to_string()),
      secret: Some(b"hello world mfkdf2!!".to_vec()),
      ..Default::default()
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
      digits: Some(5), // Too small
      ..Default::default()
    };
    let result_low = hotp(options_low);
    assert!(matches!(result_low, Err(crate::error::MFKDF2Error::InvalidHOTPDigits)));

    let options_4 = HOTPOptions {
      digits: Some(4), // Too small
      ..Default::default()
    };
    let result_4 = hotp(options_4);
    assert!(matches!(result_4, Err(crate::error::MFKDF2Error::InvalidHOTPDigits)));

    // Upper bound
    let options_high = HOTPOptions {
      digits: Some(9), // Too large
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
      digits: Some(6),
      hash:   Some(HashAlgorithm::Sha1),
      issuer: Some("MFKDF".to_string()),
      label:  Some("test".to_string()),
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

    let params = hotp_factor.params(key.into()).unwrap();
    assert!(params.is_object());

    let pad_b64 = params["pad"].as_str().unwrap();
    let pad = BASE64_STANDARD.decode(pad_b64).unwrap();

    let decrypted_secret = crate::crypto::decrypt(pad, &key);

    assert_eq!(
      &decrypted_secret[..hotp_factor.config.secret.len()],
      &hotp_factor.config.secret[..]
    );
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

    let code = generate_otp_token(
      &hotp_factor.config.secret[..20],
      1,
      &hotp_factor.config.hash,
      hotp_factor.config.digits,
    );

    let expected_offset = mod_positive(
      i64::from(hotp_factor.target) - i64::from(code),
      10_i64.pow(hotp_factor.config.digits),
    );

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
    let options = HOTPOptions { digits: Some(5), ..Default::default() };
    let result = hotp(options);
    assert!(matches!(result, Err(crate::error::MFKDF2Error::InvalidHOTPDigits)));
  }

  #[test]
  fn invalid_digits_too_high() {
    let options = HOTPOptions { digits: Some(9), ..Default::default() };
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
