pub mod bytearray;
pub mod mfkdf_derived_key;
use serde::{Deserialize, Serialize};
#[cfg(feature = "bindings")] mod uniffi_types;

pub mod entropy;
pub mod factor;

pub use bytearray::{ByteArray, Key, Salt};
pub use entropy::MFKDF2Entropy;
pub use factor::{FactorMetadata, FactorType, MFKDF2Factor};
pub use mfkdf_derived_key::MFKDF2DerivedKey;

/// Options for setting up a key.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Serialize, Deserialize)]
pub struct MFKDF2Options {
  /// ID of the policy. If not provided, a random UUID will be generated.
  pub id:        Option<String>,
  /// Threshold number of factors needed to derive the key.
  /// Minimum number of factors is 1, maximum is the number of factors provided.
  pub threshold: Option<u8>,
  /// 32 byte salt for key derivation. If not provided, a random salt will be generated.
  pub salt:      Option<Salt>,
  /// Flag to use a stack key for key derivation.
  pub stack:     Option<bool>,
  /// Flag to perform integrity checks for the policy.
  /// Default is true.
  pub integrity: Option<bool>,
  /// Additional time cost for argon2id key derivation.
  /// Default is 0.
  pub time:      Option<u32>,
  /// Additional memory cost for argon2id key derivation.
  /// Default is 0.
  pub memory:    Option<u32>,
}

impl Default for MFKDF2Options {
  fn default() -> Self {
    let mut salt = [0u8; 32];
    crate::rng::fill_bytes(&mut salt);

    Self {
      id:        Some(uuid::Uuid::new_v4().to_string()),
      threshold: None,
      salt:      Some(salt.into()),
      stack:     None,
      integrity: Some(true),
      time:      Some(0),
      memory:    Some(0),
    }
  }
}
