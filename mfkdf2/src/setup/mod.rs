pub mod factors;
pub mod key;

pub use key::key;
use serde::{Serialize, de::DeserializeOwned};

use crate::{definitions::key::Key, error::MFKDF2Result};

#[allow(unused_variables)]
pub trait FactorSetup: Send + Sync + std::fmt::Debug {
  type Params: Serialize + DeserializeOwned + std::fmt::Debug + Default;
  type Output: Serialize + DeserializeOwned + std::fmt::Debug + Default;

  fn bytes(&self) -> Vec<u8>;
  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    Ok(serde_json::from_value(serde_json::json!({}))?)
  }
  fn output(&self, key: Key) -> Self::Output { Self::Output::default() }
}
