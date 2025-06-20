use serde::{Deserialize, Serialize};
use serde_json::Value;
pub mod password;
pub mod question;
pub mod uuid;

// TODO: Need to get the name of "material" and "factorpolicy" correct.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Factor {
  pub id:     String,
  pub kind:   String,
  pub pad:    String, // base64-encoded encrypted share
  pub salt:   String, // base64 HKDF salt
  pub params: Value,  // factor-specific metadata (empty for now)
}

/// Runtime representation of a factor supplied during setup.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Material {
  pub id:      Option<String>,
  pub kind:    String,
  pub data:    Vec<u8>,
  pub output:  Value, // diagnostics (unused for now)
  pub entropy: u32,
}

impl Material {
  pub fn set_id(&mut self, id: impl Into<String>) { self.id = Some(id.into()); }
}

impl IntoIterator for Material {
  type IntoIter = std::vec::IntoIter<Self>;
  type Item = Self;

  fn into_iter(self) -> Self::IntoIter { vec![self].into_iter() }
}
