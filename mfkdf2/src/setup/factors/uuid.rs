use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub use uuid::Uuid;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorTrait, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct UUIDOptions {
  pub id:   Option<String>,
  pub uuid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct UUID {
  pub uuid: String,
}

impl FactorTrait for UUID {
  fn kind(&self) -> String { "uuid".to_string() }

  fn bytes(&self) -> Vec<u8> { self.uuid.as_bytes().to_vec() }

  fn params_setup(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output_setup(&self, _key: [u8; 32]) -> Value {
    json!({
      "uuid": self.uuid.clone(),
    })
  }

  fn params_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn include_params(&mut self, _params: Value) {}
}

pub fn uuid(options: UUIDOptions) -> MFKDF2Result<MFKDF2Factor> {
  let id = match options.id {
    None => Some("uuid".to_string()),
    Some(ref id) => {
      if id.is_empty() {
        return Err(MFKDF2Error::InvalidUuid);
      }
      Some(id.clone())
    },
  };

  let uuid = match options.uuid {
    None => Uuid::new_v4(),
    Some(ref uuid) => {
      if uuid.is_empty() {
        return Err(MFKDF2Error::InvalidUuid);
      }
      Uuid::parse_str(uuid).map_err(|_| MFKDF2Error::InvalidUuid)?
    },
  };

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    id,
    factor_type: FactorType::UUID(UUID { uuid: uuid.to_string() }),
    salt: salt.to_vec(),
    entropy: Some(122),
  })
}

#[uniffi::export]
pub fn setup_uuid(options: UUIDOptions) -> MFKDF2Result<MFKDF2Factor> { uuid(options) }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_uuid() {
    let options = UUIDOptions { id: Some("test".to_string()), uuid: None };
    let factor = uuid(options).unwrap();
    assert_eq!(factor.id, Some("test".to_string()));
    assert_eq!(factor.factor_type.kind(), "uuid");
    assert_eq!(factor.salt.len(), 32);
    assert_eq!(factor.entropy, Some(122));
  }
}
