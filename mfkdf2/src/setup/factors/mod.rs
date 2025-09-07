use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::Value;
// pub mod hmacsha1;
// pub mod hotp;
pub mod password;
// pub mod question;
// pub mod stack;
// pub mod uuid;

// pub use hmacsha1::hmacsha1;
// pub use hotp::hotp;
pub use password::password;

// pub use question::question;
// pub use stack::stack;
// pub use uuid::uuid;
use crate::setup::factors::password::{FactorTrait, FactorType};

pub type SetupFactorFn = Box<dyn Fn([u8; 32]) -> Pin<Box<dyn Future<Output = Value>>>>;

#[derive(Serialize, Deserialize)]
pub struct MFKDF2Factor {
  // TODO (autoparallel): This should be called "type" instead.
  pub kind:    String,
  pub id:      String,
  pub data:    FactorType,
  // pub data:    Vec<u8>,
  // TODO (autoparallel): This is the factor specific salt.
  pub salt:    [u8; 32],
  // #[serde(skip)]
  // pub params:  Option<SetupFactorFn>,
  pub entropy: Option<u32>,
  // #[serde(skip)]
  // pub output:  Option<SetupFactorFn>,
  // #[serde(skip)]
  // pub inner: Option<Box<dyn FactorTrait>>,
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
