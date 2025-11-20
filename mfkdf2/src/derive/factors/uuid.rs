//! UUID factor derive
//!
//! Derive phase [UUID](`crate::setup::factors::uuid`) construction. It turns a stable
//! UUID value into an [`MFKDF2Factor`] used during the derive phase. It is typically used in flows
//! where a device, account, or hardware identifier is known at both setup and derive and acts as a
//! non‑interactive high‑entropy factor
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

/// Factor construction derive phase for a UUID factor
///
/// # Example
///
/// Single‑factor setup/derive using a UUID factor within KeySetup/KeyDerive:
///
/// ```rust
/// # use std::collections::HashMap;
/// # use uuid::Uuid;
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   setup::{
/// #     self,
/// #     factors::uuid::{uuid as setup_uuid, UUIDOptions},
/// #     key::MFKDF2Options,
/// #   },
/// #   derive,
/// # };
/// # use mfkdf2::derive::factors::uuid as derive_uuid;
/// #
/// # fn main() -> MFKDF2Result<()> {
/// let id = Uuid::parse_str("f9bf78b9-54e7-4696-97dc-5e750de4c592").unwrap();
/// let setup_factor = setup_uuid(UUIDOptions { id: Some("uuid".into()), uuid: Some(id) }).unwrap();
/// let setup_key = setup::key(&[setup_factor], MFKDF2Options::default())?;
///
/// let derive_factor = derive_uuid(id)?;
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("uuid".to_string(), derive_factor)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok(())
/// # }
/// ```
pub fn uuid(uuid: Uuid) -> MFKDF2Result<MFKDF2Factor> {
  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::UUID(UUIDFactor { uuid }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_uuid(uuid: Uuid) -> MFKDF2Result<MFKDF2Factor> {
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
