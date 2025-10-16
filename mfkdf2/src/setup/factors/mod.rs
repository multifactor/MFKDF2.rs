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
  definitions::{FactorMetadata, FactorType, Key},
  error::MFKDF2Result,
  setup::{FactorSetup, Setup},
};
// impl FactorType {
// pub fn setup(&self) -> &dyn FactorSetup<Params = Value, Output = Value> {
//   match self {
//     FactorType::Password(password) => password,
//     FactorType::HOTP(hotp) => hotp,
//     FactorType::Question(question) => question,
//     FactorType::UUID(uuid) => uuid,
//     FactorType::HmacSha1(hmacsha1) => hmacsha1,
//     FactorType::TOTP(totp) => totp,
//     FactorType::OOBA(ooba) => ooba,
//     FactorType::Passkey(passkey) => passkey,
//     FactorType::Stack(stack) => stack,
//     FactorType::Persisted(_) =>
//       unreachable!("Persisted factor should not be used in this context"),
//   }
// }
// }

impl FactorSetup for FactorType<Setup> {
  type Output = Value;
  type Params = Value;

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    match self {
      FactorType::Password(password) => password.params(key),
      FactorType::HOTP(hotp) => hotp.params(key),
      FactorType::Question(question) => question.params(key),
      FactorType::UUID(uuid) => uuid.params(key),
      FactorType::HmacSha1(hmacsha1) => hmacsha1.params(key),
      FactorType::TOTP(totp) => totp.params(key),
      FactorType::OOBA(ooba) => ooba.params(key),
      FactorType::Passkey(passkey) => passkey.params(key),
      FactorType::Stack(stack) => stack.params(key),
      FactorType::Persisted(_) =>
        unreachable!("Persisted factor should not be used in this context"),
      FactorType::Phantom(_) => unreachable!("Phantom factor should not be used in this context"),
    }
  }

  fn output(&self, key: Key) -> Self::Output {
    match self {
      FactorType::Password(password) => password.output(key),
      FactorType::HOTP(hotp) => hotp.output(key),
      FactorType::Question(question) => question.output(key),
      FactorType::UUID(uuid) => uuid.output(key),
      FactorType::HmacSha1(hmacsha1) => hmacsha1.output(key),
      FactorType::TOTP(totp) => totp.output(key),
      FactorType::OOBA(ooba) => ooba.output(key),
      FactorType::Passkey(passkey) => passkey.output(key),
      FactorType::Stack(stack) => stack.output(key),
      FactorType::Persisted(_) =>
        unreachable!("Persisted factor should not be used in this context"),
      FactorType::Phantom(_) => unreachable!("Phantom factor should not be used in this context"),
    }
  }
}

// Standalone exported functions for FFI
// #[cfg_attr(feature = "bindings", uniffi::export)]
// pub fn factor_type_kind(factor_type: &FactorType) -> String { factor_type.kind() }

// #[cfg_attr(feature = "bindings", uniffi::export)]
// pub fn factor_type_bytes(factor_type: &FactorType) -> Vec<u8> { factor_type.bytes() }

// #[cfg_attr(feature = "bindings", uniffi::export)]
// pub fn setup_factor_type_params(
//   factor_type: &FactorType<Setup>,
//   key: Option<Key>,
// ) -> MFKDF2Result<Value> {
//   // TODO (@lonerapier): remove dummy key usage
//   let key = key.unwrap_or_else(|| [0u8; 32].into());
//   factor_type.params(key)
// }

// #[cfg_attr(feature = "bindings", uniffi::export)]
// pub fn setup_factor_type_output(factor_type: &FactorType<Setup>, key: Option<Key>) -> Value {
//   let key = key.unwrap_or_else(|| [0u8; 32].into());
//   factor_type.output(key)
// }
