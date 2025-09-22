use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};

use crate::{
  crypto::{decrypt, encrypt},
  derive::FactorDerive,
  error::MFKDF2Result,
  setup::factors::{Factor, FactorType, MFKDF2Factor, hmacsha1::HmacSha1},
};

impl FactorDerive for HmacSha1 {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.params = Some(serde_json::to_string(&params).unwrap());

    let response = self.response.as_ref().unwrap();
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(response);

    let pad = params["pad"]
      .as_array()
      .unwrap() // TODO (@lonerapier): use a proper error here?
      .iter()
      .map(|v| v.as_u64().unwrap() as u8)
      .collect::<Vec<u8>>();

    let padded_secret = decrypt(pad, &padded_key);
    self.padded_secret = padded_secret;

    Ok(())
  }

  fn params_derive(&self, _key: [u8; 32]) -> Value {
    let mut challenge = [0u8; 64];
    OsRng.fill_bytes(&mut challenge);

    let response = crate::crypto::hmacsha1(&self.padded_secret[..20], &challenge);
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(&response);
    let pad = encrypt(&self.padded_secret, &padded_key);

    json!({
      "challenge": challenge.to_vec(),
      "pad": pad,
    })
  }

  fn output_derive(&self) -> Value {
    json!({
      "secret": self.padded_secret[..20],
    })
  }
}

impl Factor for HmacSha1 {}

pub fn hmacsha1(response: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> {
  if response.len() != 20 {
    return Err(crate::error::MFKDF2Error::InvalidHmacResponse);
  }

  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::HmacSha1(HmacSha1 {
      response:      Some(response),
      params:        None,
      padded_secret: [0u8; 32].to_vec(),
    }),
    salt:        [0u8; 32].to_vec(),
    entropy:     Some(160),
  })
}

#[uniffi::export]
pub fn derive_hmacsha1(response: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::hmacsha1(response)
}
