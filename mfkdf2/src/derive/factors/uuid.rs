use serde_json::json;
use uuid::Uuid;

use crate::{
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorType, MFKDF2Factor, uuid::UUID},
};

impl FactorDerive for UUID {
  fn include_params(&mut self, _params: serde_json::Value) -> MFKDF2Result<()> { Ok(()) }

  fn params(&self, _key: [u8; 32]) -> serde_json::Value { json!({}) }

  fn output(&self) -> serde_json::Value {
    json!({
      "uuid": self.uuid.clone(),
    })
  }
}

pub fn uuid(uuid: String) -> MFKDF2Result<MFKDF2Factor> {
  let _ = Uuid::parse_str(&uuid).map_err(|_| MFKDF2Error::InvalidUuid)?;

  Ok(MFKDF2Factor {
    id:          None,
    factor_type: crate::derive::FactorDeriveType::UUID(UUID { uuid }),
    entropy:     Some(0),
    salt:        [0u8; 32].to_vec(),
  })
}

#[uniffi::export]
pub fn derive_uuid(uuid: String) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::uuid(uuid)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn valid() {
    let valid_uuid = "f9bf78b9-54e7-4696-97dc-5e750de4c592";
    let result = uuid(valid_uuid.to_string());
    assert!(result.is_ok());
    let factor = result.unwrap();
    let factor_uuid = match factor.factor_type {
      FactorType::UUID(u) => u.uuid,
      _ => panic!("Wrong factor type"),
    };
    assert_eq!(factor_uuid, valid_uuid);
  }

  #[test]
  fn invalid() {
    let invalid_uuid = "not-a-uuid";
    let result = uuid(invalid_uuid.to_string());
    assert!(matches!(result, Err(MFKDF2Error::InvalidUuid)));
  }

  #[test]
  fn output() {
    let valid_uuid = "f9bf78b9-54e7-4696-97dc-5e750de4c592";
    let factor = uuid(valid_uuid.to_string()).unwrap();
    let output = factor.factor_type.output();
    assert_eq!(output, json!({ "uuid": valid_uuid }));
  }

  #[test]
  fn params() {
    let valid_uuid = "f9bf78b9-54e7-4696-97dc-5e750de4c592";
    let mut factor = uuid(valid_uuid.to_string()).unwrap();

    // Test include_params (does nothing)
    let result = factor.factor_type.include_params(json!({}));
    assert!(result.is_ok());

    // Test params_derive (returns empty)
    let params = factor.factor_type.params([0; 32]);
    assert_eq!(params, json!({}));
  }
}
