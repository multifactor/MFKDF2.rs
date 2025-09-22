pub mod factors;
pub mod key;

pub use key::key;
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

impl FactorDerive for FactorType {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.inner_mut().include_params(params)
  }

  fn params_derive(&self, key: [u8; 32]) -> Value { self.inner().params_derive(key) }

  fn output_derive(&self) -> Value { self.inner().output_derive() }
}
