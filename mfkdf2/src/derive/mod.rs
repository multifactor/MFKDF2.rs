pub mod factors;
pub mod key;

pub use key::key;
use serde_json::Value;

use crate::{definitions::key::Key, error::MFKDF2Result, setup::factors::FactorType};

// #[uniffi::export]
pub trait FactorDerive: Send + Sync {
  // TODO (@lonerapier): uniffi doesn't support mutable reference to self in a trait, so only option
  // is to use interior mutability pattern
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()>;
  // TODO (@lonerapier): wrap the return value in result here too
  fn params(&self, key: Key) -> Value;
  fn output(&self) -> Value;
}

impl FactorType {
  fn derive(&self) -> &dyn FactorDerive {
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

  fn derive_mut(&mut self) -> &mut dyn FactorDerive {
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

impl FactorDerive for FactorType {
  // TODO: add associated types for params
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.derive_mut().include_params(params)
  }

  fn params(&self, key: Key) -> Value { self.derive().params(key) }

  fn output(&self) -> Value { self.derive().output() }
}

// #[uniffi::export]
// pub fn derive_factor_include_params(
//   factor: std::sync::Arc<std::sync::Mutex<FactorType>>,
//   params: Value,
// ) -> MFKDF2Result<()> {
//   let mut factor_mut = factor.lock().unwrap();
//   factor_mut.include_params(params)
// }

#[uniffi::export]
pub fn derive_factor_params(factor: &FactorType, key: Key) -> Value { factor.params(key) }

#[uniffi::export]
pub fn derive_factor_output(factor: &FactorType) -> Value { factor.output() }
