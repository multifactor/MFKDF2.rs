use serde_json::{Value, json};

use crate::{
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{Factor, FactorType, MFKDF2Factor, passkey::Passkey},
};

impl FactorDerive for Passkey {
  fn include_params(&mut self, _params: Value) -> MFKDF2Result<()> {
    // Passkey factor has no parameters from setup
    Ok(())
  }

  fn params_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output_derive(&self, _key: [u8; 32]) -> Value { json!({}) }
}
impl Factor for Passkey {}

pub fn passkey(secret: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> {
  if secret.len() != 32 {
    return Err(MFKDF2Error::InvalidPasskeySecretLength);
  }

  Ok(MFKDF2Factor {
    id:          Some("passkey".to_string()),
    factor_type: FactorType::Passkey(Passkey { secret }),
    salt:        [0u8; 32].to_vec(),
    entropy:     None,
  })
}
