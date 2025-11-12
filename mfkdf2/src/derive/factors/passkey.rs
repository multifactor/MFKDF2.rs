use serde_json::Value;

use crate::{
  definitions::{FactorType, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::passkey::Passkey,
};

impl FactorDerive for Passkey {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, _params: Self::Params) -> MFKDF2Result<()> {
    // Passkey factor has no parameters from setup
    Ok(())
  }
}

pub fn passkey(secret: [u8; 32]) -> MFKDF2Result<MFKDF2Factor> {
  Ok(MFKDF2Factor {
    id:          Some("passkey".to_string()),
    factor_type: FactorType::Passkey(Passkey { secret: secret.to_vec() }),
    entropy:     None,
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn derive_passkey(secret: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> {
  if secret.len() != 32 {
    return Err(MFKDF2Error::InvalidSecretLength("passkey".to_string()));
  }

  passkey(secret.try_into().unwrap())
}
