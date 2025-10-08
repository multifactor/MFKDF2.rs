use std::collections::HashMap;

use base64::engine::general_purpose;
use serde::{Deserialize, Serialize};

use crate::{definitions::entropy::MFKDF2Entropy, policy::Policy};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct MFKDF2DerivedKey {
  pub policy:  Policy,
  // TODO (@lonerapier): move to uniffi custom type
  pub key:     Vec<u8>,
  pub secret:  Vec<u8>,
  pub shares:  Vec<Vec<u8>>,
  pub outputs: HashMap<String, String>,
  pub entropy: MFKDF2Entropy,
}

impl std::fmt::Display for MFKDF2DerivedKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "MFKDF2DerivedKey {{ key: {}, secret: {} }}",
      base64::Engine::encode(&general_purpose::STANDARD, self.key.clone()),
      base64::Engine::encode(&general_purpose::STANDARD, self.secret.clone()),
    )
  }
}
