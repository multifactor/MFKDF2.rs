pub mod factors;
pub mod key;

pub use key::key;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{error::MFKDF2Result, setup::factors::FactorType};

pub trait FactorDerive {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()>;
  // TODO (@lonerapier): wrap the return value in result here too
  fn params_derive(&self, key: [u8; 32]) -> Value;
  fn output_derive(&self) -> Value;
}

impl FactorDerive for FactorType {
  // TODO: add associated types for params
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.inner_mut().include_params(params)
  }

  fn params_derive(&self, key: [u8; 32]) -> Value { self.inner().params_derive(key) }

  fn output_derive(&self) -> Value { self.inner().output_derive() }
}
use crate::{
  derive::factors::stack,
  setup::factors::{hmacsha1, hotp, ooba, passkey, password, question, totp, uuid},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Enum)]
pub enum FactorDeriveType {
  Password(password::Password),
  HOTP(hotp::HOTP),
  Question(question::Question),
  UUID(uuid::UUID),
  HmacSha1(hmacsha1::HmacSha1),
  TOTP(totp::TOTP),
  OOBA(ooba::Ooba),
  Passkey(passkey::Passkey),
  Stack(stack::DeriveStack),
}

impl FactorDeriveType {
  pub fn inner(&self) -> &dyn FactorDeriveTrait {
    match self {
      FactorDeriveType::Password(password) => password,
      FactorDeriveType::HOTP(hotp) => hotp,
      FactorDeriveType::Question(question) => question,
      FactorDeriveType::UUID(uuid) => uuid,
      FactorDeriveType::HmacSha1(hmacsha1) => hmacsha1,
      FactorDeriveType::TOTP(totp) => totp,
      FactorDeriveType::OOBA(ooba) => ooba,
      FactorDeriveType::Passkey(passkey) => passkey,
      FactorDeriveType::Stack(stack) => stack,
    }
  }

  pub fn inner_mut(&mut self) -> &mut dyn FactorDeriveTrait {
    match self {
      FactorDeriveType::Password(password) => password,
      FactorDeriveType::HOTP(hotp) => hotp,
      FactorDeriveType::Question(question) => question,
      FactorDeriveType::UUID(uuid) => uuid,
      FactorDeriveType::HmacSha1(hmacsha1) => hmacsha1,
      FactorDeriveType::TOTP(totp) => totp,
      FactorDeriveType::OOBA(ooba) => ooba,
      FactorDeriveType::Passkey(passkey) => passkey,
      FactorDeriveType::Stack(stack) => stack,
    }
  }
}

impl FactorDeriveTrait for FactorDeriveType {
  fn kind(&self) -> String { self.inner().kind() }

  fn bytes(&self) -> Vec<u8> { self.inner().bytes() }

  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.inner_mut().include_params(params)
  }

  fn params_derive(&self, key: [u8; 32]) -> Value { self.inner().params_derive(key) }

  fn output_derive(&self, key: [u8; 32]) -> Value { self.inner().output_derive(key) }
}
