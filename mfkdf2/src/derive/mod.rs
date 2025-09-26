pub mod factors;
pub mod key;

pub use key::key;
use serde_json::Value;

use crate::{error::MFKDF2Result, setup::factors::FactorType};

pub trait FactorDerive {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()>;
  // TODO (@lonerapier): wrap the return value in result here too
  fn params(&self, key: [u8; 32]) -> Value;
  fn output(&self) -> Value;
}

impl FactorType {
  pub fn derive(&self) -> &dyn FactorDerive {
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

  pub fn derive_mut(&mut self) -> &mut dyn FactorDerive {
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

  fn params(&self, key: [u8; 32]) -> Value { self.derive().params(key) }

  fn output(&self) -> Value { self.derive().output() }
}

impl FactorDerive for FactorType {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.inner_mut().include_params(params)
  }

  fn params_derive(&self, key: [u8; 32]) -> Value { self.inner().params_derive(key) }

  fn output_derive(&self) -> Value { self.inner().output_derive() }
}
