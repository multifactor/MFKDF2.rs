pub mod factors;
pub mod key;

pub use key::key;
use serde_json::Value;

use crate::{
  definitions::{factor::FactorType, key::Key},
  error::MFKDF2Result,
};

#[allow(unused_variables)]
pub trait FactorDerive: Send + Sync + std::fmt::Debug {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()>;
  fn params(&self, key: Key) -> MFKDF2Result<Value> { Ok(serde_json::json!({})) }
  fn output(&self) -> Value { serde_json::json!({}) }
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

  fn params(&self, key: Key) -> MFKDF2Result<Value> { self.derive().params(key) }

  fn output(&self) -> Value { self.derive().output() }
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derive_factor_params(factor: &FactorType, key: Key) -> MFKDF2Result<Value> {
  factor.params(key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derive_factor_output(factor: &FactorType) -> Value { factor.output() }
