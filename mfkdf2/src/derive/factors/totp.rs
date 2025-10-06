#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(target_arch = "wasm32")]
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{
  crypto::decrypt,
  definitions::key::Key,
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{
    FactorType, MFKDF2Factor,
    hotp::{OTPHash, generate_hotp_code, mod_positive},
    totp::{TOTP, TOTPOptions},
  },
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct TOTPDeriveOptions {
  pub time:   Option<u64>,
  pub oracle: Option<Vec<u32>>,
}

impl Default for TOTPDeriveOptions {
  fn default() -> Self { Self { time: None, oracle: None } }
}

impl From<TOTPDeriveOptions> for TOTPOptions {
  fn from(options: TOTPDeriveOptions) -> Self {
    let mut totp_options = TOTPOptions::default();
    totp_options.time = options.time;
    totp_options.oracle = options.oracle;
    totp_options
  }
}

impl FactorDerive for TOTP {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.params = serde_json::to_string(&params)
      .map_err(|e| MFKDF2Error::InvalidDeriveParams(format!("invalid params: {}", e)))?;

    // TODO (@lonerapier): create a type for factor params and serialize/deser using that.
    let step = params
      .get("step")
      .and_then(Value::as_u64)
      .ok_or(MFKDF2Error::MissingDeriveParams("step".to_string()))?;
    let window = params
      .get("window")
      .and_then(Value::as_u64)
      .ok_or(MFKDF2Error::MissingDeriveParams("window".to_string()))?;
    let digits = params
      .get("digits")
      .and_then(Value::as_u64)
      .ok_or(MFKDF2Error::MissingDeriveParams("digits".to_string()))?;
    let start = params
      .get("start")
      .and_then(Value::as_u64) // TODO (@lonerapier): time is u128, but is being serialized to u64
      .ok_or(MFKDF2Error::MissingDeriveParams("start".to_string()))?;
    let offsets_b64 = params
      .get("offsets")
      .and_then(Value::as_str)
      .ok_or(MFKDF2Error::MissingDeriveParams("offsets".to_string()))?;
    let offsets = base64::prelude::BASE64_STANDARD.decode(offsets_b64).map_err(|e| {
      MFKDF2Error::InvalidDeriveParams(format!("invalid base64 for offsets: {}", e))
    })?;

    let start_counter = start / (step * 1000);
    let time_ms = self.options.time.ok_or(MFKDF2Error::MissingDeriveParams("time".to_string()))?;
    let now_counter = time_ms / (step * 1000);

    let index = (now_counter - start_counter) as usize;
    if index >= window as usize {
      return Err(MFKDF2Error::TOTPWindowExceeded);
    }

    let offset_start = index * 4;
    let offset_end = offset_start + 4;
    if offsets.len() < offset_end {
      return Err(MFKDF2Error::InvalidDeriveParams(
        "offsets array is too small for the current index".to_string(),
      ));
    }
    let mut offset =
      u32::from_be_bytes(offsets[offset_start..offset_end].try_into().map_err(|_| {
        MFKDF2Error::InvalidDeriveParams("failed to read 4-byte offset from offsets".to_string())
      })?);

    let oracle_time = (now_counter * step * 1000) as usize;
    if self.options.oracle.is_some() && self.options.oracle.as_ref().unwrap().len() > oracle_time {
      offset = mod_positive(
        offset as i64 - self.options.oracle.as_ref().unwrap()[oracle_time] as i64,
        10_i64.pow(digits as u32),
      ) as u32;
    }
    self.target =
      mod_positive(offset as i64 + self.code as i64, 10_i64.pow(self.options.digits as u32)) as u32;

    Ok(())
  }

  /// Note: `self.options` is only used for [`TOTPDeriveOptions`].
  fn params(&self, key: Key) -> Value {
    let params: Value = serde_json::from_str(&self.params).unwrap();

    let pad = params["pad"].as_str().unwrap();
    let pad = base64::prelude::BASE64_STANDARD.decode(pad).unwrap();
    let padded_secret = decrypt(pad.clone(), &key.0);

    let window = params["window"].as_u64().unwrap();
    let step = params["step"].as_u64().unwrap();
    let digits = params["digits"].as_u64().unwrap();
    let hash = params["hash"].as_str().unwrap();
    let hash = match hash {
      "sha1" => OTPHash::Sha1,
      "sha256" => OTPHash::Sha256,
      "sha512" => OTPHash::Sha512,
      _ => panic!("Unsupported hash algorithm"),
    };

    let time = self.options.time.unwrap() as u128;
    let mut new_offsets = Vec::with_capacity((4 * window) as usize);

    for i in 0..window {
      let counter = (time / 1000) as u64 / step + i;
      let code = generate_hotp_code(&padded_secret[..20], counter, &hash, digits as u8);

      let mut offset =
        mod_positive(self.target as i64 - code as i64, 10_i64.pow(digits as u32)) as u32;

      let oracle_time = (counter * step * 1000) as usize;
      if self.options.oracle.is_some() && self.options.oracle.as_ref().unwrap().len() > oracle_time
      {
        offset = mod_positive(
          offset as i64 - self.options.oracle.as_ref().unwrap()[oracle_time] as i64,
          10_i64.pow(digits as u32),
        ) as u32;
      }

      new_offsets.extend_from_slice(&offset.to_be_bytes());
    }

    json!({
      "start": time,
      "hash": match hash {
          OTPHash::Sha1 => "sha1",
          OTPHash::Sha256 => "sha256",
          OTPHash::Sha512 => "sha512",
      },
      "digits": digits,
      "step": step,
      "window": window,
      "pad": base64::prelude::BASE64_STANDARD.encode(&pad),
      "offsets": base64::prelude::BASE64_STANDARD.encode(&new_offsets),
    })
  }

  fn output(&self) -> Value { json!({}) }
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
      options: options.into(),
      params: serde_json::to_string(&Value::Null).unwrap(),
      code,
      target: 0,
    }),
    salt:        [0u8; 32].to_vec(),
    entropy:     Some(0), // TODO (@lonerapier): is entropy used anywhere after derive?
  })
}

#[uniffi::export]
pub async fn derive_totp(
  code: u32,
  options: Option<TOTPDeriveOptions>,
) -> MFKDF2Result<MFKDF2Factor> {
  log::debug!("derive_totp options: {:?}", options);
  totp(code, options)
}

#[cfg(test)]
mod tests {
  use std::time::SystemTime;

  use super::*;
  use crate::setup::factors::totp as setup_totp;

  fn get_test_derive_totp_options(time: Option<u64>) -> TOTPDeriveOptions {
    TOTPDeriveOptions { time, oracle: None }
  }

  fn get_test_totp_options() -> TOTPOptions {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

    setup_totp::TOTPOptions {
      id:     Some("totp-test".to_string()),
      secret: Some(b"hello world mfkdf2!!".to_vec()),
      digits: 6,
      hash:   OTPHash::Sha1,
      step:   30,
      window: 5,
      time:   Some(now_ms),
      oracle: None,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    }
  }

  fn factor_params_for_test() -> Value {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let offsets = vec![0u8; 4 * 5]; // 4 bytes per offset * window size
    json!({
      "digits": 6,
      "hash": "sha1",
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
    let step = setup_options.step;
    let digits = setup_options.digits;
    let hash = setup_options.hash.clone();
    let time = setup_options.time.unwrap();

    let factor = setup_totp::totp(setup_options).unwrap();

    let secret = if let FactorType::TOTP(f) = &factor.factor_type {
      f.options.secret.as_ref().unwrap().clone()
    } else {
      panic!("wrong factor type");
    };

    let mock_key = [42u8; 32];
    let setup_params = factor.factor_type.setup().params(mock_key.into());

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
    let setup_params = factor.factor_type.setup().params(mock_key.into());

    let derive_options = get_test_derive_totp_options(None);
    let mut derive_factor = totp(123456, Some(derive_options)).unwrap();
    derive_factor.factor_type.include_params(setup_params.clone()).unwrap();

    let derive_params = derive_factor.factor_type.params(mock_key.into());

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
    let setup_params = factor.factor_type.setup().params(mock_key.into());

    let future_time_ms = start_time_ms + (30 * 10 * 1000); // 10 steps into the future, outside of window 5
    let derive_options = get_test_derive_totp_options(Some(future_time_ms));
    let mut derive_material = totp(123456, Some(derive_options)).unwrap();

    let result = derive_material.factor_type.include_params(setup_params);
    assert!(matches!(result, Err(MFKDF2Error::TOTPWindowExceeded)));
  }

  #[test]
  fn totp_include_params_missing_step() {
    let mut derive_factor = totp(123456, None).unwrap();
    let mut params = factor_params_for_test();
    params["step"] = Value::Null;
    let result = derive_factor.factor_type.include_params(params);
    assert!(matches!(result, Err(MFKDF2Error::MissingDeriveParams(s)) if s == "step"));
  }

  #[test]
  fn totp_include_params_missing_window() {
    let mut derive_factor = totp(123456, None).unwrap();
    let mut params = factor_params_for_test();
    params["window"] = Value::Null;
    let result = derive_factor.factor_type.include_params(params);
    assert!(matches!(result, Err(MFKDF2Error::MissingDeriveParams(s)) if s == "window"));
  }
}
