use serde_json::json;
use uuid::Uuid;

use crate::{
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{Factor, FactorType, MFKDF2Factor, uuid::UUID},
};

impl FactorDerive for UUID {
  fn include_params(&mut self, _params: serde_json::Value) -> MFKDF2Result<()> { Ok(()) }

  fn params_derive(&self, _key: [u8; 32]) -> serde_json::Value { json!({}) }

  fn output_derive(&self, _key: [u8; 32]) -> serde_json::Value {
    json!({
      "uuid": self.uuid.clone(),
    })
  }
}
impl Factor for UUID {}

pub fn uuid(uuid: String) -> MFKDF2Result<MFKDF2Factor> {
  let _ = Uuid::parse_str(&uuid).map_err(|_| MFKDF2Error::InvalidUuid)?;

  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::UUID(UUID { uuid }),
    entropy:     Some(0),
    salt:        [0u8; 32].to_vec(),
  })
}

#[uniffi::export]
pub fn derive_uuid(uuid: String) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::uuid(uuid)
}
