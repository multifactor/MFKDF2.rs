use serde_json::json;
use uuid::Uuid;

use crate::{
  definitions::{FactorType, MFKDF2Factor},
  derive::FactorDerive,
  error::MFKDF2Result,
  setup::factors::uuid::UUIDFactor,
};

impl FactorDerive for UUIDFactor {
  type Output = serde_json::Value;
  type Params = serde_json::Value;

  fn include_params(&mut self, _params: Self::Params) -> MFKDF2Result<()> { Ok(()) }

  fn output(&self) -> Self::Output {
    json!({
      "uuid": self.uuid.clone(),
    })
  }
}

pub fn uuid(uuid: Uuid) -> MFKDF2Result<MFKDF2Factor> {
  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::UUID(UUIDFactor { uuid }),
    entropy:     None,
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn derive_uuid(uuid: Uuid) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::uuid(uuid)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn valid() {
    let valid_uuid = "f9bf78b9-54e7-4696-97dc-5e750de4c592";
    let result = uuid(Uuid::parse_str(valid_uuid).unwrap());
    assert!(result.is_ok());
    let factor = result.unwrap();
    let factor_uuid = match factor.factor_type {
      FactorType::UUID(u) => u.uuid,
      _ => panic!("Wrong factor type"),
    };
    assert_eq!(factor_uuid, Uuid::parse_str(valid_uuid).unwrap());
  }

  #[test]
  fn output() {
    let valid_uuid = "f9bf78b9-54e7-4696-97dc-5e750de4c592";
    let factor = uuid(Uuid::parse_str(valid_uuid).unwrap()).unwrap();
    let output = factor.factor_type.output();
    assert_eq!(output, json!({ "uuid": valid_uuid }));
  }

  #[test]
  fn params() {
    let valid_uuid = "f9bf78b9-54e7-4696-97dc-5e750de4c592";
    let mut factor = uuid(Uuid::parse_str(valid_uuid).unwrap()).unwrap();

    // Test include_params (does nothing)
    let result = factor.factor_type.include_params(json!({}));
    assert!(result.is_ok());

    // Test params_derive (returns empty)
    let params = factor.factor_type.params([0; 32].into()).unwrap();
    assert_eq!(params, json!({}));
  }
}
