use std::collections::HashMap;

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  classes::mfkdf_derived_key::MFKDF2DerivedKey,
  error::{MFKDF2Error, MFKDF2Result},
  setup::{
    factors::{FactorMetadata, FactorSetup, FactorType, MFKDF2Factor},
    key::{self, MFKDF2Options},
  },
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct StackOptions {
  pub id:        Option<String>,
  pub threshold: Option<u8>,
  pub salt:      Option<Vec<u8>>,
}

impl Into<MFKDF2Options> for StackOptions {
  fn into(self) -> MFKDF2Options {
    MFKDF2Options {
      id:        self.id,
      threshold: self.threshold,
      salt:      self.salt,
      stack:     Some(true),
      integrity: Some(false),
      time:      None,
      memory:    None,
    }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Stack {
  pub factors: HashMap<String, MFKDF2Factor>,
  pub key:     MFKDF2DerivedKey,
}

impl FactorMetadata for Stack {
  fn kind(&self) -> String { "stack".to_string() }
}

impl FactorSetup for Stack {
  fn bytes(&self) -> Vec<u8> { self.key.key.clone() }

  fn params_setup(&self, _key: [u8; 32]) -> Value {
    serde_json::to_value(&self.key.policy).unwrap_or(json!({}))
  }

  fn output_setup(&self, _key: [u8; 32]) -> Value {
    serde_json::to_value(&self.key).unwrap_or(json!({}))
  }
}

pub async fn stack(
  factors: Vec<MFKDF2Factor>,
  options: StackOptions,
) -> MFKDF2Result<MFKDF2Factor> {
  let id = match options.id {
    None => Some("stack".to_string()),
    Some(ref id) => {
      if id.is_empty() {
        return Err(MFKDF2Error::MissingFactorId);
      }
      Some(id.clone())
    },
  };

  let mfkdf_options: MFKDF2Options = options.into();
  let key = key::key(factors.clone(), mfkdf_options).await?;

  // per-factor salt
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  let mut factor_map = HashMap::new();
  let _ = factors.into_iter().map(|f| factor_map.insert(f.id.clone().unwrap(), f));

  Ok(MFKDF2Factor {
    id,
    factor_type: FactorType::Stack(Stack { factors: factor_map, key: key.clone() }),
    salt: salt.to_vec(),
    entropy: Some(key.entropy.real),
  })
}

#[uniffi::export]
pub async fn setup_stack(
  factors: Vec<MFKDF2Factor>,
  options: StackOptions,
) -> MFKDF2Result<MFKDF2Factor> {
  stack(factors, options).await
}
