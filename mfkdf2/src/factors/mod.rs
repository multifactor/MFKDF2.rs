use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::MFKDF2Result;
pub mod password;
pub mod question;
pub mod uuid;

pub trait FactorMaterial {
  type Params;
  type Output;
  fn material(self) -> MFKDF2Result<GenericFactor<Self>>
  where Self: Sized;
}

/// A scaffold for a factor in the MFKDF2 algorithm.
pub struct GenericFactor<T: FactorMaterial> {
  pub id:     String,
  pub data:   T,
  pub params: T::Params,
  pub output: T::Output,
}

// TODO: Need to get the name of "material" and "factorpolicy" correct.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct FactorPolicy {
  pub id:     String,
  #[serde(rename = "type")]
  pub kind:   String,
  pub pad:    String, // base64-encoded encrypted share
  pub salt:   String, // base64 HKDF salt
  pub params: Value,  // factor-specific metadata (empty for now)
}

/// Runtime representation of a factor supplied during setup.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Material {
  pub id:     String,
  pub kind:   String,
  pub data:   Vec<u8>,
  pub output: String, // diagnostics (unused for now)
}

// From the JS implementation:
// * @typedef MFKDFFactor
// * @type {object}
// * @property {string} type
// * @property {string} [id]
// * @property {Buffer} data
// * @property {function} params
// * @property {number} [entropy]
// * @property {function} [output]
