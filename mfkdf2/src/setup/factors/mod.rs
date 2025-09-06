use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::Value;
pub mod hmacsha1;
// pub mod hotp;
// pub mod password;
// pub mod question;
// pub mod stack;
// pub mod uuid;

pub use hmacsha1::hmacsha1;
// pub use hotp::hotp;
// pub use password::password;
// pub use question::question;
// pub use stack::stack;
// pub use uuid::uuid;

pub type SetupFactorFn = Box<dyn Fn() -> Pin<Box<dyn Future<Output = Value>>> + Send + Sync>;

#[derive(Serialize, Deserialize, uniffi::Record)]
pub struct MFKDF2Factor {
  // TODO (autoparallel): This should be called "type" instead.
  pub kind:    String,
  pub id:      String,
  pub data:    Vec<u8>,
  // TODO (autoparallel): This is the factor specific salt.
  pub salt:    Vec<u8>,
  #[serde(skip)]
  // TODO (autoparallel): This should be a map, but i'm storing a string for now..
  pub params: String,
  pub entropy: Option<u32>,
  #[serde(skip)]
  pub output:  String,
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
