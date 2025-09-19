use serde_json::json;
use uuid::Uuid;

use crate::{
  derive::{FactorDeriveTrait, factors::MFKDF2DeriveFactor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorType, uuid::UUID},
};

impl FactorDeriveTrait for UUID {
  fn kind(&self) -> String { "uuid".to_string() }

  fn bytes(&self) -> Vec<u8> { self.uuid.as_bytes().to_vec() }

  fn include_params(&mut self, _params: serde_json::Value) -> MFKDF2Result<()> { Ok(()) }

  fn params_derive(&self, _key: [u8; 32]) -> serde_json::Value { json!({}) }

  fn output_derive(&self, _key: [u8; 32]) -> serde_json::Value {
    json!({
      "uuid": self.uuid.clone(),
    })
  }
}

pub fn uuid(uuid: String) -> MFKDF2Result<MFKDF2DeriveFactor> {
  let _ = Uuid::parse_str(&uuid).map_err(|_| MFKDF2Error::InvalidUuid)?;

  Ok(MFKDF2DeriveFactor {
    id:          None,
    factor_type: FactorType::UUID(UUID { uuid }),
    entropy:     Some(0),
    salt:        [0u8; 32].to_vec(),
  })
}

#[uniffi::export]
pub fn derive_uuid(uuid: String) -> MFKDF2Result<MFKDF2DeriveFactor> {
  crate::derive::factors::uuid(uuid)
}
