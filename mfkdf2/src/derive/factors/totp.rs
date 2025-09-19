use std::time::SystemTime;

use base64::Engine;
use serde_json::{Value, json};

use crate::{
  crypto::decrypt,
  derive::{FactorDeriveTrait, factors::MFKDF2DeriveFactor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{
    FactorSetupType,
    hotp::{OTPHash, generate_hotp_code, mod_positive},
    totp::{TOTP, TOTPOptions},
  },
};
// #[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
// pub struct TOTPDeriveOptions {
//   pub time:   Option<SystemTime>,
//   pub oracle: Option<bool>,
// }

impl FactorDeriveTrait for TOTP {
  fn kind(&self) -> String { "totp".to_string() }

  fn bytes(&self) -> Vec<u8> { self.target.to_be_bytes().to_vec() }

  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.params = serde_json::to_string(&params).unwrap();

    let step = params["step"].as_u64().unwrap();
    let window = params["window"].as_u64().unwrap();
    let digits = params["digits"].as_u64().unwrap();

    let offsets: Vec<u8> =
      params["offsets"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let start_counter = params["start"].as_u64().unwrap() / (step * 1000);
    let now_counter =
      self.options.time.unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64
        / (step * 1000);

    let index = (now_counter - start_counter) as usize;
    if index >= window as usize {
      return Err(MFKDF2Error::TOTPWindowExceeded);
    }

    let mut offset = offsets[index] as u32;
    let oracle_time = (now_counter * step * 1000) as usize;
    if self.options.oracle.is_some() && self.options.oracle.as_ref().unwrap().len() > oracle_time {
      offset = mod_positive(
        (offset - self.options.oracle.as_ref().unwrap()[oracle_time]) as i64,
        10_i64.pow(digits as u32),
      ) as u32;
    }
    self.target =
      mod_positive(offset as i64 + self.code as i64, 10_i64.pow(self.options.digits as u32)) as u32;

    Ok(())
  }

  fn params_derive(&self, key: [u8; 32]) -> Value {
    let params: Value = serde_json::from_str(&self.params).unwrap();

    let pad = params["pad"].as_str().unwrap();
    let pad = base64::prelude::BASE64_STANDARD.decode(pad).unwrap();
    let padded_secret = decrypt(pad.clone(), &key);

    let time =
      self.options.time.unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
    let mut new_offsets = Vec::with_capacity((4 * self.options.window) as usize);

    for i in 0..self.options.window {
      let counter = (time / 1000) as u64 / self.options.step + i;
      let code =
        generate_hotp_code(&padded_secret[..20], counter, &self.options.hash, self.options.digits);

      let mut offset =
        mod_positive(self.target as i64 - code as i64, 10_i64.pow(self.options.digits as u32))
          as u32;

      let oracle_time = (counter * self.options.step * 1000) as usize;
      if self.options.oracle.is_some() && self.options.oracle.as_ref().unwrap().len() > oracle_time
      {
        offset = mod_positive(
          (offset - self.options.oracle.as_ref().unwrap()[oracle_time]) as i64,
          10_i64.pow(self.options.digits as u32),
        ) as u32;
      }

      new_offsets.extend_from_slice(&offset.to_be_bytes());
    }

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
        "offsets": base64::prelude::BASE64_STANDARD.encode(&new_offsets),
    })
  }

  fn output_derive(&self, _key: [u8; 32]) -> Value { json!({}) }
}

pub fn totp(code: u32, options: TOTPOptions) -> MFKDF2Result<MFKDF2DeriveFactor> {
  let mut options = options;

  // Validation
  if options.time.is_none() {
    options.time = Some(SystemTime::now());
  }

  Ok(MFKDF2DeriveFactor {
    id:          Some("totp".to_string()),
    factor_type: crate::derive::FactorDeriveType::TOTP(TOTP {
      options,
      params: serde_json::to_string(&Value::Null).unwrap(),
      code,
      target: 0,
    }),
    salt:        [0u8; 32].to_vec(),
    entropy:     Some(0), // TODO (@lonerapier): is entropy used anywhere after derive?
  })
}
