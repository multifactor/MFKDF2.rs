//! # MFKDF2 Key Setup
//! An MFKDF Key Instance Kᵢ is a tuple (βᵢ, key) representing the i-th derivation of the key.
//! Initial derivation of the key is performed by [`KeySetup`](`crate::setup::key::key`) that takes
//! [factor instances](`crate::definitions::factor::MFKDF2Factor`) and produces the
//! [`MFKDF2DerivedKey`](`crate::definitions::MFKDF2DerivedKey`).
pub mod factors;
mod key;

pub use key::key;
use serde::{Deserialize, Serialize};

use crate::{definitions::Key, error::MFKDF2Result};

/// Trait for factor setup.
pub(crate) trait FactorSetup {
  /// Public parameters for the factor setup.
  type Params: Serialize + for<'de> Deserialize<'de>;
  /// Public output for the factor setup.
  type Output: Serialize + for<'de> Deserialize<'de>;

  /// Returns the public parameters for the factor setup.
  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params>;
  /// Returns the public output for the factor setup.
  fn output(&self) -> Self::Output;
}
