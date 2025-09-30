use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub use uuid::Uuid;

use crate::{
  definitions::key::Key,
  error::MFKDF2Result,
  setup::factors::{FactorMetadata, FactorSetup, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct UUIDOptions {
  pub id:   Option<String>,
  pub uuid: Option<Uuid>,
}

impl Default for UUIDOptions {
  fn default() -> Self { Self { id: Some("uuid".to_string()), uuid: None } }
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct UUIDFactor {
  pub uuid: Uuid,
}

uniffi::custom_type!(Uuid, String, {
  remote,
  lower: |v| v.to_string(),
  try_lift: |s: String| Uuid::parse_str(&s).map_err(uniffi::deps::anyhow::Error::msg),
});

impl FactorMetadata for UUIDFactor {
  fn kind(&self) -> String { "uuid".to_string() }
}

impl FactorSetup for UUIDFactor {
  fn bytes(&self) -> Vec<u8> { self.uuid.as_bytes().to_vec() }

  fn params(&self, _key: Key) -> Value { json!({}) }

  fn output(&self, _key: Key) -> Value {
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

  println!("options: {:?}", options);

  let uuid = options.uuid.unwrap_or(Uuid::new_v4());

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    id:          Some(options.id.unwrap_or("uuid".to_string())),
    factor_type: FactorType::UUID(UUIDFactor { uuid }),
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
    let options = UUIDOptions {
      id:   Some("test_valid".to_string()),
      uuid: Some(Uuid::parse_str(valid_uuid).unwrap()),
    };
    let factor = uuid(options).unwrap();
    let factor_uuid = match factor.factor_type {
      FactorType::UUID(u) => u.uuid,
      _ => panic!("Wrong factor type"),
    };
    assert_eq!(factor_uuid, Uuid::parse_str(valid_uuid).unwrap());
  }

  #[test]
  fn with_empty_id() {
    let options = UUIDOptions { id: Some("".to_string()), uuid: None };
    let result = uuid(options);
    assert!(matches!(result, Err(crate::error::MFKDF2Error::MissingFactorId)));
  }

  #[test]
  fn default_options() {
    let options = UUIDOptions::default();
    let factor = uuid(options).unwrap();
    assert_eq!(factor.id, Some("uuid".to_string()));
  }
}
