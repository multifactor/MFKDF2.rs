use serde_json::{Value, json};

use crate::{
  definitions::key::Key,
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorType, MFKDF2Factor, passkey::Passkey},
};

impl FactorDerive for Passkey {
  fn include_params(&mut self, _params: Value) -> MFKDF2Result<()> {
    // Passkey factor has no parameters from setup
    Ok(())
  }

  fn params(&self, _key: Key) -> Value { json!({}) }

  fn output(&self) -> Value { json!({}) }
}

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

#[uniffi::export]
pub async fn derive_passkey(secret: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> { passkey(secret) }
