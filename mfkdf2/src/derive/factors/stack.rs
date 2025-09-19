use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  derive::{FactorDeriveTrait, factors::MFKDF2DeriveFactor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::{
    factors::FactorSetupType,
    key::{MFKDF2DerivedKey, Policy},
  },
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct DeriveStack {
  pub factors: HashMap<String, MFKDF2DeriveFactor>,
  pub key:     MFKDF2DerivedKey,
}

impl FactorDeriveTrait for DeriveStack {
  fn kind(&self) -> String { "stack".to_string() }

  fn bytes(&self) -> Vec<u8> { self.key.key.clone() }

  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    // Stack factors don't need to include params during derivation
    // The key derivation is handled by the derive_key function
    let policy: Policy = serde_json::from_value(params)
      .map_err(|_| MFKDF2Error::InvalidDeriveParams("params".to_string()))?;
    self.key = crate::derive::key(policy, self.factors.clone(), false, true)?;
    Ok(())
  }

  fn params_derive(&self, _key: [u8; 32]) -> Value {
    // Return the policy as params, similar to the JS version
    serde_json::to_value(&self.key.policy).unwrap_or(json!({}))
  }

  fn output_derive(&self, _key: [u8; 32]) -> Value {
    // Return the full key object, similar to the JS version
    serde_json::to_value(&self.key).unwrap_or(json!({}))
  }
}

pub fn stack(factors: HashMap<String, MFKDF2DeriveFactor>) -> MFKDF2Result<MFKDF2DeriveFactor> {
  if factors.is_empty() {
    return Err(MFKDF2Error::InvalidDeriveParams("factors".to_string()));
  }

  Ok(MFKDF2DeriveFactor {
    id:          Some("stack".to_string()),
    factor_type: crate::derive::FactorDeriveType::Stack(DeriveStack {
      factors,
      key: MFKDF2DerivedKey::default(),
    }),
    salt:        [0u8; 32].to_vec(),
    entropy:     None,
  })
}
