pub mod factors;
pub mod key;

pub use key::key;
use serde_json::Value;

use crate::error::MFKDF2Result;

pub trait FactorDeriveTrait {
  fn kind(&self) -> String;
  fn bytes(&self) -> Vec<u8>;
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()>;
  // TODO (@lonerapier): wrap the return value in result here too
  fn params_derive(&self, key: [u8; 32]) -> Value;
  fn output_derive(&self, key: [u8; 32]) -> Value;
}
