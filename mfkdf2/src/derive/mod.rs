pub mod factors;
pub mod key;

pub use key::key;
use serde_json::Value;

use crate::{
  definitions::{FactorType, Key},
  error::MFKDF2Result,
};

#[allow(unused_variables)]
pub trait FactorDerive: Send + Sync + std::fmt::Debug {
  type Params: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + Default;
  type Output: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + Default;

  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()>;
  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    Ok(serde_json::from_value(serde_json::json!({}))?)
  }
  fn output(&self) -> Self::Output { Self::Output::default() }
}

impl FactorType {
  fn derive(&self) -> &dyn FactorDerive<Params = Value, Output = Value> {
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
      FactorType::Persisted(persisted) => persisted,
    }
  }

  fn derive_mut(&mut self) -> &mut dyn FactorDerive<Params = Value, Output = Value> {
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
      FactorType::Persisted(persisted) => persisted,
    }
  }
}

impl FactorDerive for FactorType {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    self.derive_mut().include_params(params)
  }

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> { self.derive().params(key) }

  fn output(&self) -> Self::Output { self.derive().output() }
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derive_factor_params(factor: &FactorType, key: Key) -> MFKDF2Result<Value> {
  factor.params(key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derive_factor_output(factor: &FactorType) -> Value { factor.output() }
