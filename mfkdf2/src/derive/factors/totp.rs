use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(target_arch = "wasm32")]
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{
  crypto::decrypt,
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  otpauth::generate_hotp_code,
  setup::factors::{
    hotp::mod_positive,
    totp::{TOTP, TOTPConfig, TOTPParams},
  },
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TOTPDeriveOptions {
  pub time:   Option<u64>,
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
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    self.params = params.clone();

    let params: TOTPParams = serde_json::from_value(params)?;

    let start_counter = params.start / (params.step * 1000);
    let now_counter = self.config.time / (params.step * 1000);

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
    let offsets = base64::prelude::BASE64_STANDARD.decode(params.offsets)?;
    let mut offset =
      u32::from_be_bytes(offsets[offset_start..offset_end].try_into().map_err(|_| {
        MFKDF2Error::InvalidDeriveParams("failed to read 4-byte offset from offsets".to_string())
      })?);

    let oracle_time = now_counter * params.step * 1000;
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

    Ok(())
  }

  /// Note: `self.options` is only used for [`TOTPDeriveOptions`].
  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    let params: TOTPParams = serde_json::from_value(self.params.clone())?;

    let pad = base64::prelude::BASE64_STANDARD.decode(params.pad)?;
    let padded_secret = decrypt(pad.clone(), &key.0);

    let time = params.start;
    let mut new_offsets = Vec::with_capacity((4 * params.window) as usize);

    for i in 0..params.window {
      let counter = (time / 1000) as u64 / params.step + i;
      let code = generate_hotp_code(&padded_secret[..20], counter, &params.hash, params.digits);

      let mut offset =
        mod_positive(i64::from(self.target) - i64::from(code), 10_i64.pow(params.digits));

      let oracle_time = counter * params.step * 1000;
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
      hash:    params.hash,
      digits:  params.digits,
      step:    params.step,
      window:  params.window,
      pad:     base64::prelude::BASE64_STANDARD.encode(&pad),
      offsets: base64::prelude::BASE64_STANDARD.encode(&new_offsets),
    };

    Ok(serde_json::to_value(params)?)
  }
}

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
      params: Value::Null,
      code,
      target: 0,
    }),
    entropy:     None,
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn derive_totp(
  code: u32,
  options: Option<TOTPDeriveOptions>,
) -> MFKDF2Result<MFKDF2Factor> {
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

  fn factor_params_for_test() -> Value {
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
    let setup_params = factor.factor_type.setup().params(mock_key.into()).unwrap();

    let now_millis = time;
    let counter = now_millis / (step * 1000);

    let correct_code = generate_hotp_code(&secret[..20], counter, &hash, digits);

    let derive_options = get_test_derive_totp_options(Some(time));
    let mut derive_material = totp(correct_code, Some(derive_options)).unwrap();

    derive_material.factor_type.include_params(setup_params).unwrap();

    let derived_target = derive_material.data();
    assert_ne!(derived_target, 0_u32.to_be_bytes());
  }

  #[test]
  fn totp_derive_params() {
    let setup_options = get_test_totp_options();
    let factor = setup_totp::totp(setup_options).unwrap();
    let mock_key = [42u8; 32];
    let setup_params = factor.factor_type.setup().params(mock_key.into()).unwrap();

    let derive_options = get_test_derive_totp_options(None);
    let mut derive_factor = totp(123456, Some(derive_options)).unwrap();
    derive_factor.factor_type.include_params(setup_params.clone()).unwrap();

    let derive_params = derive_factor.factor_type.params(mock_key.into()).unwrap();

    let original_start = setup_params["start"].as_u64().unwrap();
    let new_start = derive_params["start"].as_u64().unwrap();
    assert!(new_start >= original_start);

    let new_offsets_b64 = derive_params["offsets"].as_str().unwrap();
    let new_offsets = base64::prelude::BASE64_STANDARD.decode(new_offsets_b64).unwrap();
    assert_eq!(new_offsets.len(), 4 * 5); // 4 bytes per offset * window size
  }

  #[test]
  fn totp_window_exceeded() {
    let mut setup_options = get_test_totp_options();
    let start_time_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    setup_options.time = Some(start_time_ms);

    let factor = setup_totp::totp(setup_options).unwrap();
    let mock_key = [42u8; 32];
    let setup_params = factor.factor_type.setup().params(mock_key.into()).unwrap();

    let future_time_ms = start_time_ms + (30 * 10 * 1000); // 10 steps into the future, outside of window 5
    let derive_options = get_test_derive_totp_options(Some(future_time_ms));
    let mut derive_material = totp(123456, Some(derive_options)).unwrap();

    let result = derive_material.factor_type.include_params(setup_params);
    assert!(matches!(result, Err(MFKDF2Error::TOTPWindowExceeded)));
  }

  #[test]
  #[should_panic]
  fn totp_include_params_missing_step() {
    let mut derive_factor = totp(123456, None).unwrap();
    let mut params = factor_params_for_test();
    params["step"] = Value::Null;
    let result = derive_factor.factor_type.include_params(params);
    assert!(matches!(result, Err(MFKDF2Error::MissingDeriveParams(s)) if s == "step"));
  }

  #[test]
  #[should_panic]
  fn totp_include_params_missing_window() {
    let mut derive_factor = totp(123456, None).unwrap();
    let mut params = factor_params_for_test();
    params["window"] = Value::Null;
    let result = derive_factor.factor_type.include_params(params);
    assert!(matches!(result, Err(MFKDF2Error::MissingDeriveParams(s)) if s == "window"));
  }
}
