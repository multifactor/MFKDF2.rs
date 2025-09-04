use serde::{Deserialize, Serialize};
use serde_json::Value;
pub mod hotp;
pub mod password;
pub mod question;
pub mod uuid;

#[derive(uniffi::Object, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Factor {
  pub id:     String,
  pub kind:   String,
  pub pad:    String, // base64-encoded encrypted share
  pub salt:   String, // base64 HKDF salt
  pub key:    [u8; 32],
  pub secret: Vec<u8>,
  pub params: Value, // factor-specific metadata (empty for now)
}

/// I'm writing some documentation for this here. Use it by doing:
/// ```
/// let material = Material {
///   id:      Some("my-id".to_string()),
///   kind:    "my-kind".to_string(),
///   data:    vec![1, 2, 3],
///   output:  Value::Null,
///   entropy: 100,
/// };
/// ```
#[derive(uniffi::Object, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
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

pub trait Derive {
  type Input;
  type Output;

  fn derive(input: Self::Input) -> Self::Output;
}

pub trait Setup {
  type Input;
  type Output;

  fn setup(input: Self::Input) -> Self::Output;
}
