use serde::{Deserialize, Serialize};

pub mod hmacsha1;
pub mod hotp;
pub mod ooba;
pub mod passkey;
pub mod password;
pub mod question;
pub mod stack;
pub mod totp;
pub mod uuid;

pub use hmacsha1::hmacsha1;
pub use hotp::hotp;
pub use ooba::ooba;
pub use passkey::passkey;
pub use password::password;
pub use question::question;
pub use stack::stack;
pub use totp::totp;
pub use uuid::uuid;

use crate::derive::FactorDeriveType;

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct MFKDF2DeriveFactor {
  pub id:          Option<String>,
  // TODO (@lonerapier): create a new derive factor type
  pub factor_type: FactorDeriveType,
  // TODO (autoparallel): This is the factor specific salt.
  pub salt:        Vec<u8>,
  pub entropy:     Option<u32>,
}
