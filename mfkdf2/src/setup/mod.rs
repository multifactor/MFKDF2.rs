//! # KeySetup
//! An MFKDF Key Instance Kᵢ is a tuple (βᵢ, key) representing the i-th derivation of the key.
//! Initial derivation of the key is performed by [KeySetup](`crate::setup::key::key`) that takes
//! [factor instances](`crate::definitions::factor::MFKDF2Factor`) and produces the
//! [MFKDF2DerivedKey](`crate::definitions::MFKDF2DerivedKey`).
//!
//! # FactorSetup
//! Every [Factor](`crate::definitions::MFKDF2Factor`) instance is constructed using Witness
//! Wᵢ and parameters βᵢ. Each factor uses [FactorSetup](`crate::setup::FactorSetup`) that takes
//! secret material σᵢ to produce the initial parameters β₀ given some configuration and randomly
//! generated static source material κᵢ. The factor’s public state βᵢ then stores an encrypted
//! version of σᵢ (using the key feedback mechanism) and public helper data.
pub mod factors;
pub mod key;

pub use key::key;
use serde::{Deserialize, Serialize};

use crate::{definitions::Key, error::MFKDF2Result};

/// Trait for factor setup.
pub trait FactorSetup {
  /// Public parameters for the factor setup.
  type Params: Serialize + for<'de> Deserialize<'de> + Default;
  /// Public output for the factor setup.
  type Output: Serialize + for<'de> Deserialize<'de> + Default;

  /// Returns the public parameters for the factor setup.
  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> {
    Ok(serde_json::from_value(serde_json::json!({}))?)
  }
  /// Returns the public output for the factor setup.
  fn output(&self) -> Self::Output { serde_json::from_value(serde_json::json!({})).unwrap() }
}
