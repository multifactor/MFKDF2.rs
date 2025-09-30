use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  definitions::key::Key,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorMetadata, FactorSetup, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Passkey {
  pub secret: Vec<u8>,
}

impl FactorMetadata for Passkey {
  fn kind(&self) -> String { "passkey".to_string() }
}

impl FactorSetup for Passkey {
  fn bytes(&self) -> Vec<u8> { self.secret.clone() }

  fn params(&self, _key: Key) -> Value { json!({}) }

  fn output(&self, _key: Key) -> Value { json!({}) }
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct PasskeyOptions {
  pub id: Option<String>,
}

pub fn passkey(secret: Vec<u8>, options: PasskeyOptions) -> MFKDF2Result<MFKDF2Factor> {
  if secret.len() != 32 {
    return Err(MFKDF2Error::InvalidHmacKey);
  }

  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    id:          Some(options.id.unwrap_or("passkey".to_string())),
    factor_type: FactorType::Passkey(Passkey { secret }),
    salt:        salt.to_vec(),
    entropy:     Some(256),
  })
}

#[uniffi::export]
pub async fn setup_passkey(secret: Vec<u8>, options: PasskeyOptions) -> MFKDF2Result<MFKDF2Factor> {
  crate::setup::factors::passkey::passkey(secret, options)
}
