pub mod factors;
pub mod key;

pub use key::key;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{definitions::Key, error::MFKDF2Result};

#[allow(unused_variables)]
pub trait FactorSetup: std::fmt::Debug {
  type Params: Serialize + DeserializeOwned + std::fmt::Debug + Default;
  type Output: Serialize + DeserializeOwned + std::fmt::Debug + Default;

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    Ok(serde_json::from_value(serde_json::json!({}))?)
  }
  fn output(&self, key: Key) -> Self::Output { Self::Output::default() }
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub trait FactorState: std::fmt::Debug + Send + Sync {}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Setup {}
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Derive {}

impl FactorState for Setup {}
impl FactorState for Derive {}
