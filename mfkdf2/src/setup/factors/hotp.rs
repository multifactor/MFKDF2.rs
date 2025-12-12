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
use base64::engine::Engine;
use serde::{Deserialize, Serialize};

use crate::{
  crypto::encrypt,
  defaults::hotp as hotp_defaults,
  definitions::{FactorType, Key, MFKDF2Factor},
  error::MFKDF2Result,
  otpauth::{self, HashAlgorithm, OtpAuthUrlOptions, generate_otp_token},
  setup::FactorSetup,
  traits::Factor,
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
      id:     Some(hotp_defaults::ID.to_string()),
      secret: None,
      digits: Some(hotp_defaults::DIGITS),
      hash:   Some(hotp_defaults::HASH),
      issuer: Some(hotp_defaults::ISSUER.to_string()),
      label:  Some(hotp_defaults::LABEL.to_string()),
    }
  }
}

/// HOTP factor state.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTP {
  /// Application-defined identifier for the factor.
  pub id:     String,
  /// 32‑byte HOTP secret (20 bytes original + 12 bytes padding).
  pub secret: Vec<u8>,
  /// Number of digits in the OTP code (6–8).
  pub digits: u32,
  /// Hash algorithm used by the HOTP generator.
  pub hash:   HashAlgorithm,
  /// A string value indicating the provider or service the credential is associated with.
  pub issuer: String,
  /// A string value identifying which account a credential is associated with. It also serves
  /// as the unique identifier for the credential itself.
  pub label:  String,
  /// HOTP public parameters.
  pub params: Option<HOTPParams>,
  /// HOTP code.
  pub code:   u32,
  /// HOTP secret factor material. The target code that is used to derive the key.
  pub target: u32,
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for HOTP {
  fn zeroize(&mut self) {
    self.secret.zeroize();
    self.target.zeroize();
    self.code.zeroize();
  }
}

/// HOTP public parameters.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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

impl Default for HOTPParams {
  fn default() -> Self {
    Self {
      hash:    hotp_defaults::HASH,
      digits:  hotp_defaults::DIGITS,
      pad:     String::new(),
      counter: hotp_defaults::COUNTER,
      offset:  0,
    }
  }
}

/// HOTP factor output.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct HOTPOutput {
  /// OTP authentication scheme.
  pub scheme:    String,
  /// Factor type.
  #[serde(rename = "type")]
  pub type_:     String,
  /// Account label.
  pub label:     String,
  /// HOTP secret (20 bytes).
  pub secret:    Vec<u8>,
  /// Issuer name.
  pub issuer:    String,
  /// Hash algorithm.
  pub algorithm: String,
  /// Number of digits.
  pub digits:    u32,
  /// Initial counter value.
  pub counter:   u64,
  /// `OTPAuth` URI for QR code generation.
  pub uri:       String,
}

impl Factor for HOTP {
  type Output = HOTPOutput;
  type Params = HOTPParams;

  fn kind(&self) -> &'static str { "hotp" }

  fn bytes(&self) -> Vec<u8> { self.target.to_be_bytes().to_vec() }
}

impl FactorSetup for HOTP {
  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    // Generate HOTP code with counter = 1
    let code =
      generate_otp_token(&self.secret[..20], hotp_defaults::COUNTER, &self.hash, self.digits);

    // Calculate offset
    let offset = mod_positive(i64::from(self.target) - i64::from(code), 10_i64.pow(self.digits));

    let pad = encrypt(&self.secret, key.as_ref());

    Ok(HOTPParams {
      hash: self.hash.clone(),
      digits: self.digits,
      pad: base64::prelude::BASE64_STANDARD.encode(&pad),
      counter: hotp_defaults::COUNTER,
      offset,
    })
  }

  fn output(&self) -> Self::Output {
    HOTPOutput {
      scheme:    "otpauth".to_string(),
      type_:     "hotp".to_string(),
      label:     self.label.clone(),
      secret:    self.secret[..20].to_vec(),
      issuer:    self.issuer.clone(),
      algorithm: self.hash.to_string(),
      digits:    self.digits,
      counter:   hotp_defaults::COUNTER,
      uri:       otpauth::otpauth_url(&OtpAuthUrlOptions {
        secret:    hex::encode(&self.secret[..20]),
        label:     self.label.clone(),
        kind:      Some(otpauth::Kind::Hotp),
        counter:   Some(hotp_defaults::COUNTER),
        issuer:    Some(self.issuer.clone()),
        digits:    Some(self.digits),
        period:    None,
        encoding:  Some(otpauth::Encoding::Hex),
        algorithm: Some(self.hash.clone()),
      })
      .unwrap(),
    }
  }
}

/// Modulus operation to ensure the result is positive.
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
/// use mfkdf2::{
///   otpauth::HashAlgorithm,
///   setup::factors::hotp::{HOTPOptions, hotp},
/// };
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
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// Invalid digits
///
/// ```rust
/// # use mfkdf2::setup::factors::hotp::{hotp, HOTPOptions};
/// # use mfkdf2::otpauth::HashAlgorithm;
///
/// let options = HOTPOptions { digits: Some(4), ..Default::default() };
/// let result = hotp(options);
/// assert!(matches!(result, Err(mfkdf2::error::MFKDF2Error::InvalidHOTPDigits)));
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn hotp(mut options: HOTPOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let id = options.id.take().unwrap_or_else(|| hotp_defaults::ID.to_string());

  // Validate and extract digits with default
  let digits = options.digits.unwrap_or(hotp_defaults::DIGITS);
  if !(6..=8).contains(&digits) {
    return Err(crate::error::MFKDF2Error::InvalidHOTPDigits);
  }

  // TODO (@lonerapier); remove this validation later using static secret type
  // secret length validation
  if let Some(ref secret) = options.secret
    && secret.len() != 20
  {
    return Err(crate::error::MFKDF2Error::InvalidSecretLength(id.clone()));
  }
  // consume the secret from options and generate a random one if none is provided
  let secret = options.secret.take().unwrap_or_else(|| {
    let mut secret = [0u8; 20];
    crate::rng::fill_bytes(&mut secret);
    secret.to_vec()
  });

  // Generate random target
  let target = crate::rng::gen_range_u32(10_u32.pow(digits) - 1);

  // Pad secret to 32 bytes
  let mut secret_pad = [0u8; 12];
  crate::rng::fill_bytes(&mut secret_pad);
  let padded_secret = secret.into_iter().chain(secret_pad).collect();

  // Extract other fields with defaults
  let hash = options.hash.unwrap_or(hotp_defaults::HASH);
  let issuer = options.issuer.take().unwrap_or_else(|| hotp_defaults::ISSUER.to_string());
  let label = options.label.take().unwrap_or_else(|| hotp_defaults::LABEL.to_string());

  let entropy = Some(f64::from(digits) * 10.0_f64.log2());

  // TODO (autoparallel): Code should possibly be an option, though this follows the same pattern as
  // the password factor which stores the actual password in the struct.
  Ok(MFKDF2Factor {
    id: Some(id.clone()),
    factor_type: FactorType::HOTP(HOTP {
      id,
      secret: padded_secret,
      digits,
      hash,
      issuer,
      label,
      params: None,
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
  use base64::prelude::BASE64_STANDARD;

  use super::*;
  use crate::definitions::factor::FactorParams;

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
    if let FactorParams::HOTP(params) = params {
      assert_eq!(params.hash, HashAlgorithm::Sha1);
      assert_eq!(params.digits, 6);
      assert_eq!(params.counter, 1);
    }
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
    let params = factor.factor_type.setup().params(key.into());
    assert!(params.is_ok());
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

    let pad = BASE64_STANDARD.decode(params.pad).unwrap();

    let decrypted_secret = crate::crypto::decrypt(pad, &key);

    assert_eq!(&decrypted_secret[..hotp_factor.secret.len()], &hotp_factor.secret[..]);
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

    let code =
      generate_otp_token(&hotp_factor.secret[..20], 1, &hotp_factor.hash, hotp_factor.digits);

    let expected_offset =
      mod_positive(i64::from(hotp_factor.target) - i64::from(code), 10_i64.pow(hotp_factor.digits));

    assert_eq!(params.offset, expected_offset);
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
