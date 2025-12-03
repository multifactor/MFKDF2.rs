//! UUID factor setup.
//!
//! This factor uses a random (or caller‑provided) UUID as its secret material. It is useful for
//! device binding or opaque identifiers where you want stable, high‑entropy bytes that are not
//! intended to be memorized by a user.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub use uuid::Uuid;

use crate::{
  definitions::{FactorType, MFKDF2Factor, factor::FactorMetadata},
  error::MFKDF2Result,
  setup::FactorSetup,
};

/// Options for configuring a [`UUIDFactor`].
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UUIDOptions {
  /// Optional application-defined identifier for the factor. Defaults to `"uuid"`. If
  /// provided, it must be non-empty.
  pub id:   Option<String>,
  /// Optional pre‑existing UUID. If omitted, a new random UUID v4 is generated during setup.
  pub uuid: Option<Uuid>,
}

impl Default for UUIDOptions {
  fn default() -> Self { Self { id: Some("uuid".to_string()), uuid: None } }
}

/// UUID‑backed factor state.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UUIDFactor {
  /// UUID used as factor material.
  pub uuid: Uuid,
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for UUIDFactor {
  fn zeroize(&mut self) {}
}

impl FactorMetadata for UUIDFactor {
  fn kind(&self) -> String { "uuid".to_string() }

  fn bytes(&self) -> Vec<u8> { self.uuid.as_bytes().to_vec() }
}

impl FactorSetup for UUIDFactor {
  type Output = Value;
  type Params = Value;

  fn output(&self) -> Self::Output {
    json!({
      "uuid": self.uuid,
    })
  }
}

/// Creates a UUID factor from the given options.
///
/// If no UUID is supplied, a new v4 UUID is generated. The resulting factor
/// provides ~122 bits of entropy and can be used as a non‑interactive device
/// or account binding factor.
///
/// # Errors
/// - [`MFKDF2Error::MissingFactorId`](`crate::error::MFKDF2Error::MissingFactorId`) if `id` is
///   provided but empty.
///
/// # Example
///
/// ```rust
/// # use mfkdf2::setup::factors::uuid::{uuid, UUIDOptions};
/// let factor = uuid(UUIDOptions::default())?;
/// assert_eq!(factor.id.as_deref(), Some("uuid"));
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn uuid(mut options: UUIDOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }

  let uuid = options.uuid.take().unwrap_or(Uuid::new_v4());

  Ok(MFKDF2Factor {
    id:          Some(options.id.unwrap_or("uuid".to_string())),
    factor_type: FactorType::UUID(UUIDFactor { uuid }),
    entropy:     Some(122.0),
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn setup_uuid(options: UUIDOptions) -> MFKDF2Result<MFKDF2Factor> { uuid(options) }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn no_options() {
    let options = UUIDOptions { id: Some("test".to_string()), uuid: None };
    let factor = uuid(options).unwrap();
    assert_eq!(factor.id, Some("test".to_string()));
    assert_eq!(factor.kind(), "uuid");
    assert_eq!(factor.entropy, Some(122.0));
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
