use serde_json::{Value, json};

use crate::{
  derive::{FactorDeriveTrait, factors::MFKDF2DeriveFactor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorSetupType, passkey::Passkey},
};

impl FactorDeriveTrait for Passkey {
  fn kind(&self) -> String { "passkey".to_string() }

  fn bytes(&self) -> Vec<u8> { self.secret.clone() }

  fn include_params(&mut self, _params: Value) -> MFKDF2Result<()> {
    // Passkey factor has no parameters from setup
    Ok(())
  }

  fn params_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output_derive(&self, _key: [u8; 32]) -> Value { json!({}) }
}

pub fn passkey(secret: Vec<u8>) -> MFKDF2Result<MFKDF2DeriveFactor> {
  if secret.len() != 32 {
    return Err(MFKDF2Error::InvalidPasskeySecretLength);
  }

  Ok(MFKDF2DeriveFactor {
    id:          Some("passkey".to_string()),
    factor_type: crate::derive::FactorDeriveType::Passkey(Passkey { secret }),
    salt:        [0u8; 32].to_vec(),
    entropy:     None,
  })
}
