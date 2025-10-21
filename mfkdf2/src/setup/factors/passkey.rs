use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::{
  definitions::{FactorMetadata, FactorType, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::FactorSetup,
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Passkey {
  pub secret: Vec<u8>,
}

impl FactorMetadata for Passkey {
  fn kind(&self) -> String { "passkey".to_string() }

  fn bytes(&self) -> Vec<u8> { self.secret.clone() }
}

impl FactorSetup for Passkey {
  type Output = serde_json::Value;
  type Params = serde_json::Value;
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyOptions {
  pub id: Option<String>,
}

impl Default for PasskeyOptions {
  fn default() -> Self { Self { id: Some("passkey".to_string()) } }
}

pub fn passkey(secret: [u8; 32], options: PasskeyOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let id = options.id.clone().unwrap_or("passkey".to_string());

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    id:          Some(id),
    factor_type: FactorType::Passkey(Passkey { secret: secret.to_vec() }),
    salt:        salt.to_vec(),
    entropy:     Some(256.0),
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn setup_passkey(secret: Vec<u8>, options: PasskeyOptions) -> MFKDF2Result<MFKDF2Factor> {
  if secret.len() != 32 {
    return Err(MFKDF2Error::InvalidSecretLength("passkey".to_string()));
  }

  passkey(secret.try_into().unwrap(), options)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn passkey_errors() {
    let factor = passkey([0u8; 32], PasskeyOptions { id: Some("".to_string()) });
    assert!(matches!(factor, Err(MFKDF2Error::MissingFactorId)));
  }
}
