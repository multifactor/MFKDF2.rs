use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub use uuid::Uuid;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorMetadata, FactorSetup, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct UUIDOptions {
  pub id:   Option<String>,
  pub uuid: Option<String>,
}

impl Default for UUIDOptions {
  fn default() -> Self { Self { id: Some("uuid".to_string()), uuid: None } }
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct UUID {
  pub uuid: String,
}

impl FactorMetadata for UUID {
  fn kind(&self) -> String { "uuid".to_string() }
}

impl FactorSetup for UUID {
  fn bytes(&self) -> Vec<u8> { self.uuid.as_bytes().to_vec() }

  fn params(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output(&self, _key: [u8; 32]) -> Value {
    json!({
      "uuid": self.uuid.clone(),
    })
  }
}

pub fn uuid(options: UUIDOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }

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
    id:          Some(options.id.unwrap_or("uuid".to_string())),
    factor_type: FactorType::UUID(UUID { uuid: uuid.to_string() }),
    salt:        salt.to_vec(),
    entropy:     Some(122),
  })
}

#[uniffi::export]
pub async fn setup_uuid(options: UUIDOptions) -> MFKDF2Result<MFKDF2Factor> { uuid(options) }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn no_options() {
    let options = UUIDOptions { id: Some("test".to_string()), uuid: None };
    let factor = uuid(options).unwrap();
    assert_eq!(factor.id, Some("test".to_string()));
    assert_eq!(factor.kind(), "uuid");
    assert_eq!(factor.salt.len(), 32);
    assert_eq!(factor.entropy, Some(122));
  }

  #[test]
  fn with_provided_valid_uuid() {
    let valid_uuid = "f9bf78b9-54e7-4696-97dc-5e750de4c592";
    let options =
      UUIDOptions { id: Some("test_valid".to_string()), uuid: Some(valid_uuid.to_string()) };
    let factor = uuid(options).unwrap();
    let factor_uuid = match factor.factor_type {
      FactorType::UUID(u) => u.uuid,
      _ => panic!("Wrong factor type"),
    };
    assert_eq!(factor_uuid, valid_uuid);
  }

  #[test]
  fn with_invalid_uuid() {
    let invalid_uuid = "not-a-uuid";
    let options =
      UUIDOptions { id: Some("test_invalid".to_string()), uuid: Some(invalid_uuid.to_string()) };
    let result = uuid(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidUuid)));
  }

  #[test]
  fn with_empty_uuid() {
    let empty_uuid = "";
    let options =
      UUIDOptions { id: Some("test_empty_uuid".to_string()), uuid: Some(empty_uuid.to_string()) };
    let result = uuid(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidUuid)));
  }

  #[test]
  fn with_empty_id() {
    let options = UUIDOptions { id: Some("".to_string()), uuid: None };
    let result = uuid(options);
    assert!(matches!(result, Err(MFKDF2Error::MissingFactorId)));
  }

  #[test]
  fn default_options() {
    let options = UUIDOptions::default();
    let factor = uuid(options).unwrap();
    assert_eq!(factor.id, Some("uuid".to_string()));
    let factor_uuid = match factor.factor_type {
      FactorType::UUID(u) => u.uuid,
      _ => panic!("Wrong factor type"),
    };
    assert!(Uuid::parse_str(&factor_uuid).is_ok());
  }
}
