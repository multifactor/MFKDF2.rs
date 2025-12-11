//! Factor construction derive phase for the TOTP factor from
//! [TOTP](`mod@crate::setup::factors::totp`).
//!
//! - During setup, the factor precomputes a window of offsets and stores them along with an
//!   encrypted TOTP secret in the policy.
//! - During derive, this module consumes a time‑based TOTP code Wᵢⱼ and reconstructs the same
//!   target code σₜ within the configured time window, refreshing offsets for future logins
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{
  crypto::decrypt,
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  otpauth::generate_otp_token,
  setup::factors::{
    hotp::mod_positive,
    totp::{TOTP, TOTPConfig, TOTPOutput, TOTPParams},
  },
};

/// Options for configuring a TOTP factor derive.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TOTPDeriveOptions {
  /// Unix time in milliseconds used for derive; defaults to the current system time when omitted
  pub time:   Option<u64>,
  /// Optional timing oracle to harden TOTP factor construction
  pub oracle: Option<HashMap<u64, u32>>,
}

impl TryFrom<TOTPDeriveOptions> for TOTPConfig {
  type Error = MFKDF2Error;

  fn try_from(options: TOTPDeriveOptions) -> Result<Self, MFKDF2Error> {
    Ok(TOTPConfig {
      time: options.time.ok_or(MFKDF2Error::MissingDeriveParams("time".to_string()))?,
      oracle: options.oracle,
      ..Default::default()
    })
  }
}

impl FactorDerive for TOTP {
  /// Stores the public parameters for the TOTP factor.
  /// Calculates the offset index from start time and current time, and derives the target code.
  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    let start_counter = params.start / (params.step as u64 * 1000);
    let now_counter = self.config.time / (params.step as u64 * 1000);

    let index = (now_counter - start_counter) as usize;
    if index >= params.window as usize {
      return Err(MFKDF2Error::TOTPWindowExceeded);
    }

    let offset_start = index * 4;
    let offset_end = offset_start + 4;
    if params.offsets.len() < offset_end {
      return Err(MFKDF2Error::InvalidDeriveParams(
        "offsets array is too small for the current index".to_string(),
      ));
    }
    let offsets = base64::prelude::BASE64_STANDARD.decode(&params.offsets)?;
    let mut offset =
      u32::from_be_bytes(offsets[offset_start..offset_end].try_into().map_err(|_| {
        MFKDF2Error::InvalidDeriveParams("failed to read 4-byte offset from offsets".to_string())
      })?);

    let oracle_time = now_counter * (params.step as u64) * 1000;
    if self.config.oracle.is_some()
      && self.config.oracle.as_ref().unwrap().contains_key(&oracle_time)
    {
      offset = mod_positive(
        i64::from(offset)
          - i64::from(*self.config.oracle.as_ref().unwrap().get(&oracle_time).unwrap()),
        10_i64.pow(params.digits),
      );
    }
    self.target =
      mod_positive(i64::from(offset) + i64::from(self.code), 10_i64.pow(self.config.digits));

    self.params = Some(params);
    Ok(())
  }

  /// Decrypts the secret and generates the new codes in the time window.
  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    let params = self
      .params
      .as_ref()
      .ok_or_else(|| crate::error::MFKDF2Error::MissingDeriveParams("params".to_string()))?;

    let pad = base64::prelude::BASE64_STANDARD.decode(params.pad.clone())?;
    #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
    let mut padded_secret = decrypt(pad.clone(), key.as_ref());

    let time = params.start;
    let mut new_offsets = Vec::with_capacity((4 * params.window) as usize);

    for i in 0..params.window {
      let counter = (time / 1000) / (params.step as u64) + i as u64;
      let code = generate_otp_token(&padded_secret[..20], counter, &params.hash, params.digits);

      let mut offset =
        mod_positive(i64::from(self.target) - i64::from(code), 10_i64.pow(params.digits));

      let oracle_time = counter * u64::from(params.step) * 1000;
      if self.config.oracle.is_some()
        && self.config.oracle.as_ref().unwrap().contains_key(&oracle_time)
      {
        offset = mod_positive(
          i64::from(offset)
            + i64::from(*self.config.oracle.as_ref().unwrap().get(&oracle_time).unwrap()),
          10_i64.pow(params.digits),
        );
      }

      new_offsets.extend_from_slice(&offset.to_be_bytes());
    }

    let params = TOTPParams {
      start:   time,
      hash:    params.hash.clone(),
      digits:  params.digits,
      step:    params.step,
      window:  params.window,
      pad:     base64::prelude::BASE64_STANDARD.encode(&pad),
      offsets: base64::prelude::BASE64_STANDARD.encode(&new_offsets),
    };

    #[cfg(feature = "zeroize")]
    {
      use zeroize::Zeroize;
      padded_secret.zeroize();
      new_offsets.zeroize();
    }

    Ok(params)
  }

  fn output(&self) -> Self::Output {
    // Returning invalid output for TOTP
    TOTPOutput {
      scheme:    "otpauth".to_string(),
      type_:     "totp".to_string(),
      label:     "mfkdf.com".to_string(),
      secret:    vec![0u8; 20],
      issuer:    "MFKDF".to_string(),
      algorithm: "sha1".to_string(),
      digits:    0,
      period:    0,
      uri:       String::new(),
    }
  }
}

/// Factor construction derive phase for a TOTP factor
///
/// The `code` should be the numeric TOTP value displayed by a standard authenticator app that was
/// paired with the secret configured during setup. `options` can override the effective time and
/// oracle behaviour for advanced flows; by default, the current system time is used and no oracle
/// adjustments are applied.
///
/// # Errors
///
/// - [`MFKDF2Error::MissingDeriveParams`] if required fields such as "time" are missing when
///   converting [`TOTPDeriveOptions`] into [`TOTPConfig`] (this is avoided when `options` is `None`
///   and the default time is used)
/// - [`MFKDF2Error::TOTPWindowExceeded`] when the effective time lies outside the precomputed
///   window encoded in the policy
/// - [`MFKDF2Error::InvalidDeriveParams`] when the offsets buffer is malformed or too small for the
///   computed index
///
/// # Example
///
/// Single‑factor setup/derive using TOTP within KeySetup/KeyDerive:
///
/// ```rust
/// # use std::collections::HashMap;
/// # use std::time::{SystemTime, UNIX_EPOCH};
/// use mfkdf2::{
///   derive,
///   derive::factors::totp::{TOTPDeriveOptions, totp},
///   error::MFKDF2Result,
///   otpauth::HashAlgorithm,
///   setup::{
///     self,
///     factors::totp::{TOTPOptions, totp as setup_totp},
///   },
///   definitions::MFKDF2Options,
/// };
/// let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
/// let options =
///   TOTPOptions { secret: Some(b"hello world mfkdf2!!".to_vec()), ..Default::default() };
///
/// let setup_factor = setup_totp(options)?;
/// # let secret = if let mfkdf2::definitions::FactorType::TOTP(ref f) = setup_factor.factor_type {
/// #  f.config.secret.clone()
/// # } else {
/// #   unreachable!()
/// # };
/// let setup_key = setup::key(&[setup_factor], MFKDF2Options::default())?;
///
/// # let step = 30;
/// # let digits = 6;
/// # let hash = HashAlgorithm::Sha1;
/// # let counter = now_ms / (step * 1000);
/// # let code = mfkdf2::otpauth::generate_otp_token(&secret[..20], counter, &hash, digits);
///
/// let derive_options = TOTPDeriveOptions { time: Some(now_ms), oracle: None };
/// let derive_factor = totp(code, Some(derive_options))?;
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("totp".to_string(), derive_factor)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn totp(code: u32, options: Option<TOTPDeriveOptions>) -> MFKDF2Result<MFKDF2Factor> {
  let mut options = options.unwrap_or_default();

  // Validation
  if options.time.is_none() {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    options.time = Some(now_ms);
  }

  Ok(MFKDF2Factor {
    id:          Some("totp".to_string()),
    factor_type: FactorType::TOTP(TOTP {
      config: TOTPConfig::try_from(options)?,
      params: None,
      code,
      target: 0,
    }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_totp(code: u32, options: Option<TOTPDeriveOptions>) -> MFKDF2Result<MFKDF2Factor> {
  totp(code, options)
}

#[cfg(test)]
mod tests {
  use std::time::SystemTime;

  use serde_json::json;

  use super::*;
  use crate::{
    otpauth::HashAlgorithm,
    setup::factors::{totp as setup_totp, totp::TOTPOptions},
  };

  fn get_test_derive_totp_options(time: Option<u64>) -> TOTPDeriveOptions {
    TOTPDeriveOptions { time, oracle: None }
  }

  fn get_test_totp_options() -> TOTPOptions {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

    setup_totp::TOTPOptions {
      id:     Some("totp-test".to_string()),
      secret: Some(b"hello world mfkdf2!!".to_vec()),
      digits: Some(6),
      hash:   Some(HashAlgorithm::Sha1),
      step:   Some(30),
      window: Some(5),
      time:   Some(now_ms),
      oracle: None,
      issuer: Some("MFKDF".to_string()),
      label:  Some("test".to_string()),
    }
  }

  fn factor_params_for_test() -> serde_json::Value {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let offsets = vec![0u8; 4 * 5]; // 4 bytes per offset * window size
    json!({
      "digits": 6,
      "hash": HashAlgorithm::Sha1.to_string(),
      "pad": "cGFk",
      "start": now_ms,
      "step": 30,
      "window": 5,
      "offsets": base64::prelude::BASE64_STANDARD.encode(&offsets)
    })
  }

  #[test]
  fn totp_round_trip() {
    let setup_options = get_test_totp_options();
    // can't get secret here, because it will be padded inside totp()
    let step = setup_options.step.unwrap();
    let digits = setup_options.digits.unwrap();
    let hash = setup_options.hash.clone().unwrap();
    let time = setup_options.time.unwrap();

    let factor = setup_totp::totp(setup_options).unwrap();

    let secret = if let FactorType::TOTP(f) = &factor.factor_type {
      f.config.secret.clone()
    } else {
      panic!("wrong factor type");
    };

    let mock_key = [42u8; 32];
    let setup_params_enum = factor.factor_type.setup().params(mock_key.into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::TOTP(p) => p,
      _ => panic!("Expected TOTP params"),
    };

    let now_millis = time;
    let counter = now_millis / (u64::from(step) * 1000);

    let correct_code = generate_otp_token(&secret[..20], counter, &hash, digits);

    let derive_options = get_test_derive_totp_options(Some(time));
    let mut derive_material = totp(correct_code, Some(derive_options)).unwrap();

    derive_material
      .factor_type
      .include_params(crate::definitions::factor::FactorParams::TOTP(setup_params))
      .unwrap();

    let derived_target = derive_material.data();
    assert_ne!(derived_target, 0_u32.to_be_bytes());
  }

  #[test]
  fn totp_derive_params() {
    let setup_options = get_test_totp_options();
    let factor = setup_totp::totp(setup_options).unwrap();
    let mock_key = [42u8; 32];
    let setup_params_enum = factor.factor_type.setup().params(mock_key.into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::TOTP(p) => p,
      _ => panic!("Expected TOTP params"),
    };

    let derive_options = get_test_derive_totp_options(None);
    let mut derive_factor = totp(123456, Some(derive_options)).unwrap();
    derive_factor
      .factor_type
      .include_params(crate::definitions::factor::FactorParams::TOTP(setup_params.clone()))
      .unwrap();

    let derive_params_enum = derive_factor.factor_type.derive().params(mock_key.into()).unwrap();
    let derive_params = match derive_params_enum {
      crate::definitions::factor::FactorParams::TOTP(p) => p,
      _ => panic!("Expected TOTP params"),
    };

    assert!(derive_params.start >= setup_params.start);

    let new_offsets = base64::prelude::BASE64_STANDARD.decode(&derive_params.offsets).unwrap();
    assert_eq!(new_offsets.len(), 4 * 5); // 4 bytes per offset * window size
  }

  #[test]
  fn totp_window_exceeded() {
    let mut setup_options = get_test_totp_options();
    let start_time_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    setup_options.time = Some(start_time_ms);

    let factor = setup_totp::totp(setup_options).unwrap();
    let mock_key = [42u8; 32];
    let setup_params_enum = factor.factor_type.setup().params(mock_key.into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::TOTP(p) => p,
      _ => panic!("Expected TOTP params"),
    };

    let future_time_ms = start_time_ms + (30 * 10 * 1000); // 10 steps into the future, outside of window 5
    let derive_options = get_test_derive_totp_options(Some(future_time_ms));
    let mut derive_material = totp(123456, Some(derive_options)).unwrap();

    let result = derive_material
      .factor_type
      .include_params(crate::definitions::factor::FactorParams::TOTP(setup_params));
    assert!(matches!(result, Err(MFKDF2Error::TOTPWindowExceeded)));
  }

  #[test]
  fn totp_include_params_missing_step() {
    use serde_json::Value;
    let _derive_factor = totp(123456, None).unwrap();
    let mut params = factor_params_for_test();
    params["step"] = Value::Null;
    let params_result: Result<TOTPParams, _> = serde_json::from_value(params);
    assert!(params_result.is_err());
  }

  #[test]
  fn totp_include_params_missing_window() {
    use serde_json::Value;
    let _derive_factor = totp(123456, None).unwrap();
    let mut params = factor_params_for_test();
    params["window"] = Value::Null;
    let params_result: Result<TOTPParams, _> = serde_json::from_value(params);
    assert!(params_result.is_err());
  }
}
