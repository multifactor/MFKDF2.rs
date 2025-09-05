// pub mod hotp;
pub mod password;
pub mod question;
// pub mod uuid;
pub mod stack;

pub use password::password;
pub use question::question;

use crate::setup::factors::SetupFactorFn;

pub struct MFKDF2DerivedFactor {
  pub kind:   String,
  pub data:   Vec<u8>,
  pub params: Option<SetupFactorFn>,
  pub output: Option<SetupFactorFn>,
}
