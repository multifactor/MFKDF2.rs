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
pub use passkey::passkey;
pub use password::password;
pub use question::question;
use serde_json::Value;
pub use stack::stack;
pub use totp::totp;
pub use uuid::uuid;

use crate::{
  definitions::{
    factor::{FactorMetadata, FactorType},
    key::Key,
  },
  setup::FactorSetup,
};

impl FactorType {
  pub fn setup(&self) -> &dyn FactorSetup {
    match self {
      FactorType::Password(password) => password,
      FactorType::HOTP(hotp) => hotp,
      FactorType::Question(question) => question,
      FactorType::UUID(uuid) => uuid,
      FactorType::HmacSha1(hmacsha1) => hmacsha1,
      FactorType::TOTP(totp) => totp,
      FactorType::OOBA(ooba) => ooba,
      FactorType::Passkey(passkey) => passkey,
      FactorType::Stack(stack) => stack,
    }
  }
}

impl FactorSetup for FactorType {
  fn bytes(&self) -> Vec<u8> { self.setup().bytes() }

  fn params(&self, key: Key) -> Value { self.setup().params(key) }

  fn output(&self, key: Key) -> Value { self.setup().output(key) }
}

// Standalone exported functions for FFI
#[uniffi::export]
pub fn factor_type_kind(factor_type: &FactorType) -> String { factor_type.kind() }

#[uniffi::export]
pub fn factor_type_bytes(factor_type: &FactorType) -> Vec<u8> { factor_type.bytes() }

#[uniffi::export]
pub fn setup_factor_type_params(factor_type: &FactorType, key: Option<Key>) -> Value {
  // TODO (@lonerapier): remove dummy key usage
  let key = key.unwrap_or_else(|| [0u8; 32].into());
  factor_type.params(key)
}

#[uniffi::export]
pub fn setup_factor_type_output(factor_type: &FactorType, key: Option<Key>) -> Value {
  let key = key.unwrap_or_else(|| [0u8; 32].into());
  factor_type.output(key)
}
