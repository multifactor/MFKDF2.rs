use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::Value;
// pub mod hotp;
pub mod password;
// pub mod question;
// pub mod uuid;

pub use password::password;

#[derive(Serialize, Deserialize)]
pub struct MFKDF2Factor {
  // TODO (autoparallel): This should be called "type" instead.
  pub kind:    String,
  pub id:      String,
  pub data:    Vec<u8>,
  // TODO (autoparallel): This is the factor specific salt.
  pub salt:    [u8; 32],
  #[serde(skip)]
  pub params:  Option<Box<dyn Fn() -> Pin<Box<dyn Future<Output = Value> + Send>> + Send + Sync>>,
  pub entropy: Option<u32>,
  #[serde(skip)]
  pub output:
    Option<Pin<Box<dyn Fn() -> Pin<Box<dyn Future<Output = Value> + Send>> + Send + Sync>>>,
}

impl std::fmt::Debug for MFKDF2Factor {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("MFKDF2Factor")
      .field("kind", &self.kind)
      .field("id", &self.id)
      .field("data", &self.data)
      .field("salt", &self.salt)
      .field("params", &"<function>")
      .field("entropy", &self.entropy)
      .field("output", &"<future>")
      .finish()
  }
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

// pub trait Derive {
//   type Input;
//   type Output;

//   fn derive(input: Self::Input) -> Self::Output;
// }

pub trait Setup {
  type Input;
  type Output;

  fn setup(input: Self::Input) -> Self::Output;
}
