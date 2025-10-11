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
}

impl FactorSetup for Passkey {
  type Output = serde_json::Value;
  type Params = serde_json::Value;

  fn bytes(&self) -> Vec<u8> { self.secret.clone() }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    entropy:     Some(256.0),
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn setup_passkey(secret: Vec<u8>, options: PasskeyOptions) -> MFKDF2Result<MFKDF2Factor> {
  passkey(secret, options)
}
