pub mod factors;
pub mod key;

pub use key::key;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{definitions::key::Key, error::MFKDF2Result};

// TODO (@lonerapier): refactor trait system with more associated types
#[cfg_attr(feature = "bindings", uniffi::export)]
#[allow(unused_variables)]
pub trait FactorSetup: Send + Sync + std::fmt::Debug {
  type Output: Serialize + DeserializeOwned + std::fmt::Debug + Default;

  fn bytes(&self) -> Vec<u8>;
  fn params(&self, key: Key) -> MFKDF2Result<Value> { Ok(serde_json::json!({})) }
  fn output(&self, key: Key) -> Self::Output { Self::Output::default() }
}
