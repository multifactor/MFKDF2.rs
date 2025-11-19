use std::collections::HashMap;

use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
  definitions::{bytearray::Key, entropy::MFKDF2Entropy},
  policy::Policy,
};

pub mod crypto;
pub mod hints;
pub mod mfdpg;
pub mod persistence;
pub mod reconstitution;
pub mod strengthening;

///
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct MFKDF2DerivedKey {
  pub policy:  Policy,
  pub key:     Key,
  pub secret:  Vec<u8>,
  pub shares:  Vec<Vec<u8>>,
  pub outputs: HashMap<String, Value>,
  pub entropy: MFKDF2Entropy,
}

impl std::fmt::Display for MFKDF2DerivedKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "MFKDF2DerivedKey {{ key: {}, secret: {} }}",
      general_purpose::STANDARD.encode(self.key.as_ref()),
      general_purpose::STANDARD.encode(self.secret.clone()),
    )
  }
}
