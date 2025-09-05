// pub mod hotp;
pub mod password;
pub mod question;
pub mod stack;
pub mod uuid;

pub use password::password;
pub use question::question;
pub use stack::stack;
pub use uuid::uuid;

use crate::setup::factors::SetupFactorFn;

pub struct MFKDF2DerivedFactor {
  pub kind:   String,
  pub data:   Vec<u8>,
  pub params: Option<SetupFactorFn>,
  pub output: Option<SetupFactorFn>,
}
