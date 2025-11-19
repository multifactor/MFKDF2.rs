pub mod factors;
pub mod key;

pub use key::key;
use serde::{Deserialize, Serialize};

use crate::{definitions::Key, error::MFKDF2Result};

#[allow(unused_variables)]
pub trait FactorSetup: Send + Sync + std::fmt::Debug {
  type Params: Serialize + for<'de> Deserialize<'de> + std::fmt::Debug + Default;
  type Output: Serialize + for<'de> Deserialize<'de> + std::fmt::Debug + Default;

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    Ok(serde_json::from_value(serde_json::json!({}))?)
  }
  fn output(&self) -> Self::Output { serde_json::from_value(serde_json::json!({})).unwrap() }
}
