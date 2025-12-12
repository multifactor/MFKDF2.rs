//! Time-based TOTP factor setup.
//!
//! This factor models an RFC 6238 TOTP "soft token" (for example, Google
//! Authenticator or any compatible app) and the corresponding server-side logic
//! used by MFKDF2 to turn a changing time-based code into stable factor
//! material.
//!
//! Conceptually:
//! - a TOTP app holds a shared key hotkeyₜ and derives one-time codes otpₜ,ᵢ at regular time steps
//!   using a counter derived from Unix time;
//! - MFKDF2 needs a fixed secret σₜ instead of a different code each step, so a random targetₜ is
//!   chosen in the range [0, 10ᵈ) (where `d` is the number of digits) and express each observed
//!   otpₜ,ᵢ as "targetₜ plus an offset" modulo 10ᵈ.
//!
//! Let T₀ be the starting Unix time, X the TOTP step/period in seconds, and T
//! the current Unix time. TOTP is essentially HOTP with a time-based counter:
//! TOTP(K) = HOTP(K, ⌊(T − T₀) / X⌋). During setup this module:
//! - fixes an initial time T₀ (stored as `start`) and a window size `w` of future steps for which
//!   offsets will be precomputed;
//! - draws a random targetₜ ∈ [0, 10ᵈ);
//! - for each counter value in {ctr, ctr + 1, …, ctr + w − 1} corresponding to that window,
//!   computes the TOTP code otpₜ,ᵢ using hotkeyₜ and stores an offset offsetₜ,ᵢ = (targetₜ −
//!   otpₜ,ᵢ) % 10ᵈ;
//! - encrypts the padded TOTP secret under the final derived key K and exposes it as the `pad`
//!   field, alongside the packed offsets table, in the public params.
//!
//! The resulting TOTP parameters capture start time, step, window, encrypted secret and precomputed
//! offsets, and are embedded into the MFKDF2 policy. On derive, as long as the current time falls
//! within the precomputed window, the library can reconstruct the same targetₜ from an app-provided
//! otpₜ,ᵢ using the stored offset without talking to the TOTP app. All offset calculation happens
//! inside the library; the authenticator app simply shows otpₜ,ᵢ once per login as usual, and
//! remains unchanged by the presence of MFKDF2.
//!
//! Software-token based key-derivation constructions require no changes to existing authenticator
//! applications like Google Authenticator. Because the HOTP key hotkeyₜ is stored inside the factor
//! state βₜ (encrypted as the pad), the computation of new offset values happens entirely inside
//! the library's setup/derive machinery. The authenticator app is only ever asked to display otpₜ,ᵢ
//! once per login, exactly as it does today; it does not participate directly in the key-derivation
//! logic.
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{
  crypto::encrypt,
  defaults::totp as totp_defaults,
  definitions::{FactorType, Key, MFKDF2Factor},
  error::MFKDF2Result,
  otpauth::{self, HashAlgorithm, OtpAuthUrlOptions, generate_otp_token},
  setup::{FactorSetup, factors::hotp::mod_positive},
  traits::Factor,
};

/// Options for configuring a TOTP factor setup
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTPOptions {
  /// Optional application-defined identifier for the factor. Defaults to `"totp"`. If
  /// provided, it must be non-empty
  pub id:     Option<String>,
  /// 20‑byte TOTP secret. If omitted, a random secret is generated
  pub secret: Option<Vec<u8>>,
  /// Number of digits in the OTP code (6–8). Values outside this range cause
  /// [`MFKDF2Error::InvalidTOTPDigits`]
  pub digits: Option<u32>,
  /// Hash algorithm used by the TOTP generator (default: SHA‑1)
  pub hash:   Option<HashAlgorithm>,
  /// A string value indicating the provider or service the credential is associated with
  pub issuer: Option<String>,
  /// A string value identifying which account a credential is associated with. It also serves
  /// as the unique identifier for the credential itself
  pub label:  Option<String>,
  /// Starting Unix time in milliseconds used to anchor the TOTP window
  pub time:   Option<u64>,
  /// Number of TOTP steps for which offsets are precomputed (default is sized for long‑lived
  /// offline use)
  pub window: Option<u32>,
  /// Step size in seconds (the TOTP "period", default 30s)
  pub step:   Option<u32>,
  /// Optional timing oracle to harden TOTP factor construction
  pub oracle: Option<HashMap<u64, u32>>,
}

impl Default for TOTPOptions {
  fn default() -> Self {
    Self {
      id:     Some(totp_defaults::ID.to_string()),
      secret: None,
      digits: Some(totp_defaults::DIGITS),
      hash:   Some(totp_defaults::HASH),
      issuer: Some(totp_defaults::ISSUER.to_string()),
      label:  Some(totp_defaults::LABEL.to_string()),
      time:   None,
      window: Some(totp_defaults::WINDOW),
      step:   Some(totp_defaults::STEP),
      oracle: None,
    }
  }
}

/// TOTP public parameters.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TOTPParams {
  /// Starting Unix time in milliseconds used to anchor the TOTP window
  pub start:   u64,
  /// Hash algorithm used by the TOTP generator
  pub hash:    HashAlgorithm,
  /// Number of digits in the OTP code
  pub digits:  u32,
  /// Step size in seconds (the TOTP "period")
  pub step:    u32,
  /// Number of TOTP steps for which offsets are precomputed
  pub window:  u32,
  /// Base64 encoded pad
  pub pad:     String,
  /// Base64 encoded offsets table
  /// The offsets table is a sequence of 4-byte integers, one for each time window slot
  pub offsets: String,
}

/// TOTP factor state
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOTP {
  /// Application-defined identifier for the factor.
  pub id:     String,
  /// 32‑byte TOTP secret (20 bytes original + 12 bytes padding).
  pub secret: Vec<u8>,
  /// Number of digits in the OTP code (6–8).
  pub digits: u32,
  /// Hash algorithm used by the TOTP generator.
  pub hash:   HashAlgorithm,
  /// A string value indicating the provider or service the credential is associated with.
  pub issuer: String,
  /// A string value identifying which account a credential is associated with. It also serves
  /// as the unique identifier for the credential itself.
  pub label:  String,
  /// Starting Unix time in milliseconds used to anchor the TOTP window.
  pub time:   u64,
  /// Number of TOTP steps for which offsets are precomputed.
  pub window: u32,
  /// Step size in seconds (the TOTP "period").
  pub step:   u32,
  /// Optional timing oracle to harden TOTP factor construction.
  pub oracle: Option<HashMap<u64, u32>>,
  /// TOTP public parameters.
  pub params: Option<TOTPParams>,
  /// TOTP code.
  pub code:   u32,
  /// TOTP factor material. The target code that is used to derive the key.
  pub target: u32,
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for TOTP {
  fn zeroize(&mut self) {
    self.secret.zeroize();
    self.target.zeroize();
    self.code.zeroize();
  }
}

impl Factor for TOTP {
  type Output = TOTPOutput;
  type Params = TOTPParams;

  fn kind(&self) -> &'static str { "totp" }

  fn bytes(&self) -> Vec<u8> { self.target.to_be_bytes().to_vec() }
}

impl FactorSetup for TOTP {
  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    let time = u128::from(self.time);
    let mut offsets = Vec::with_capacity(4 * self.window as usize);

    for i in 0..self.window {
      // Calculate the time-step 'T' as per RFC 6238, Section 4.2.
      // T = floor((CurrentUnixTime - T0) / X)
      // Here, T0 is 0 (Unix epoch) and X is self.step.
      // We add 'i' to generate a window of future OTPs for offline use.
      let counter = (time / 1000) as u64 / u64::from(self.step) + i as u64;
      let code = generate_otp_token(&self.secret[..20], counter, &self.hash, self.digits);

      let mut offset =
        mod_positive(i64::from(self.target) - i64::from(code), 10_i64.pow(self.digits));

      let oracle_time = counter * u64::from(self.step) * 1000;
      if let Some(ref oracle) = self.oracle
        && oracle.contains_key(&oracle_time)
      {
        offset = mod_positive(
          i64::from(offset) + i64::from(oracle[&oracle_time]),
          10_i64.pow(self.digits),
        );
      }

      offsets.extend_from_slice(&offset.to_be_bytes());
    }

    let pad = encrypt(&self.secret, &key);

    Ok(TOTPParams {
      start:   time as u64,
      hash:    self.hash.clone(),
      digits:  self.digits,
      step:    self.step,
      window:  self.window,
      pad:     base64::prelude::BASE64_STANDARD.encode(&pad),
      offsets: base64::prelude::BASE64_STANDARD.encode(&offsets),
    })
  }

  fn output(&self) -> Self::Output {
    TOTPOutput {
      scheme:    "otpauth".to_string(),
      type_:     "totp".to_string(),
      label:     self.label.clone(),
      secret:    self.secret[..20].to_vec(),
      issuer:    self.issuer.clone(),
      algorithm: self.hash.to_string(),
      digits:    self.digits,
      period:    self.step,
      uri:       otpauth::otpauth_url(&OtpAuthUrlOptions {
        secret:    hex::encode(&self.secret[..20]),
        label:     self.label.clone(),
        kind:      Some(otpauth::Kind::Totp),
        counter:   None,
        issuer:    Some(self.issuer.clone()),
        digits:    Some(self.digits),
        period:    Some(self.step),
        encoding:  Some(otpauth::Encoding::Hex),
        algorithm: Some(self.hash.clone()),
      })
      .unwrap(),
    }
  }
}

/// TOTP factor output.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TOTPOutput {
  /// OTP authentication scheme.
  pub scheme:    String,
  /// Factor type.
  #[serde(rename = "type")]
  pub type_:     String,
  /// Account label.
  pub label:     String,
  /// TOTP secret (20 bytes).
  pub secret:    Vec<u8>,
  /// Issuer name.
  pub issuer:    String,
  /// Hash algorithm.
  pub algorithm: String,
  /// Number of digits.
  pub digits:    u32,
  /// Time step period in seconds.
  pub period:    u32,
  /// `OTPAuth` URI for QR code generation.
  pub uri:       String,
}

/// Initializes a TOTP factor from the given options.
///
/// Validates the configuration, generates a random target code and (optionally) secret, and returns
/// an [`MFKDF2Factor`] that can be used in MFKDF2 key setup. The factor's `output()` method exposes
/// an `otpauth://` URI suitable for QR codes, while `params()` returns encrypted secret material
/// and a precomputed offset table for each time window slot.
///
/// # Errors
/// - [`MFKDF2Error::MissingFactorId`] if `id` is provided but empty
/// - [`MFKDF2Error::InvalidTOTPDigits`] if `digits` is set outside `6..=8`
/// - [`MFKDF2Error::InvalidSecretLength`] if `secret` is provided but not exactly 20 bytes
///
/// # Example
///
/// ```rust
/// # use mfkdf2::setup::factors::totp::{totp, TOTPOptions};
/// # use mfkdf2::otpauth::HashAlgorithm;
/// let options = TOTPOptions {
///   id: Some("login-totp".into()),
///   secret: Some(b"shared-totp-secret!!".to_vec()), // 20 bytes
///   digits: Some(6),
///   ..Default::default()
/// };
/// let factor = totp(options)?;
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// Invalid secret length
///
/// ```rust
/// # use mfkdf2::setup::factors::totp::{totp, TOTPOptions};
/// # use mfkdf2::error::MFKDF2Error;
/// let options = TOTPOptions {
///   secret: Some(b"my-secret-is-super-secret-123456".to_vec()),
///   ..Default::default()
/// };
/// let result = totp(options);
/// assert!(matches!(result, Err(MFKDF2Error::InvalidSecretLength(_))));
/// # Ok::<(), MFKDF2Error>(())
/// ```
pub fn totp(mut options: TOTPOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let id = options.id.take().unwrap_or_else(|| totp_defaults::ID.to_string());

  // Validate and extract digits with default
  let digits = options.digits.unwrap_or(totp_defaults::DIGITS);
  if !(6..=8).contains(&digits) {
    return Err(crate::error::MFKDF2Error::InvalidTOTPDigits);
  }

  let secret = options.secret.take().unwrap_or_else(|| {
    let mut secret = [0u8; 20];
    crate::rng::fill_bytes(&mut secret);
    secret.to_vec()
  });
  if secret.len() != 20 {
    return Err(crate::error::MFKDF2Error::InvalidSecretLength(id.clone()));
  }

  // Extract time with default (current time if not provided)
  let time = options
    .time
    .take()
    .unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64);

  // Generate random target
  let target = crate::rng::gen_range_u32(10_u32.pow(digits) - 1);

  // Pad secret to 32 bytes
  let mut secret_pad = [0u8; 12];
  crate::rng::fill_bytes(&mut secret_pad);
  let padded_secret = secret.into_iter().chain(secret_pad).collect();

  // Extract other fields with defaults
  let hash = options.hash.unwrap_or(totp_defaults::HASH);
  let issuer = options.issuer.take().unwrap_or_else(|| totp_defaults::ISSUER.to_string());
  let label = options.label.take().unwrap_or_else(|| totp_defaults::LABEL.to_string());
  let window = options.window.unwrap_or(totp_defaults::WINDOW);
  let step = options.step.unwrap_or(totp_defaults::STEP);
  let oracle = options.oracle.take();

  let entropy = Some(f64::from(digits) * 10.0_f64.log2());

  Ok(MFKDF2Factor {
    id: Some(id.clone()),
    factor_type: FactorType::TOTP(TOTP {
      id,
      secret: padded_secret,
      digits,
      hash,
      issuer,
      label,
      time,
      window,
      step,
      oracle,
      params: None,
      code: 0,
      target,
    }),
    entropy,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn setup_totp(options: TOTPOptions) -> MFKDF2Result<MFKDF2Factor> { totp(options) }

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

    assert!(matches!(factor.factor_type, FactorType::TOTP(_)));
    if let FactorType::TOTP(totp_factor) = factor.factor_type {
      assert_eq!(totp_factor.digits, 8);
      assert_eq!(totp_factor.hash, HashAlgorithm::Sha256);
      assert_eq!(totp_factor.issuer, "TestCorp".to_string());
      assert_eq!(totp_factor.label, "tester@testcorp.com".to_string());
      assert_eq!(totp_factor.secret.len(), 32); // 20 bytes generated + 12 bytes padding
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
      assert_eq!(totp_factor.secret.len(), 32);
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

    assert_eq!(params.start, 1672531200000_u64);
    assert_eq!(params.hash, HashAlgorithm::Sha1);
    assert_eq!(params.digits, 8);
    assert_eq!(params.step, 30);
    assert_eq!(params.window, 87600);

    let pad = base64::prelude::BASE64_STANDARD.decode(params.pad).unwrap();
    let decrypted_secret = decrypt(pad, &key);
    let original_secret = totp_factor.secret.as_slice();
    assert_eq!(&decrypted_secret[..original_secret.len()], original_secret);
    let offsets = base64::prelude::BASE64_STANDARD.decode(params.offsets).unwrap();
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
    assert_eq!(output.scheme, "otpauth");
    assert_eq!(output.type_, "totp");
    assert_eq!(output.label, "mfkdf.com");
    assert_eq!(output.issuer, "MFKDF");
    assert_eq!(output.algorithm, "sha1");
    assert_eq!(output.digits, 8);
    assert_eq!(output.period, 30);
    assert_eq!(output.secret.len(), 20);
    assert_eq!(output.secret, totp_factor.secret[..20]);
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
