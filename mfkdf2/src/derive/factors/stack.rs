use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  classes::mfkdf_derived_key::MFKDF2DerivedKey,
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  policy::Policy,
  setup::factors::{Factor, FactorType, MFKDF2Factor, stack::Stack},
};
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct DeriveStack {
  pub factors: HashMap<String, MFKDF2Factor>,
  pub key:     MFKDF2DerivedKey,
}

impl FactorDerive for Stack {
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

  fn output_derive(&self) -> Value {
    // Return the full key object, similar to the JS version
    serde_json::to_value(&self.key).unwrap_or(json!({}))
  }
}
impl Factor for Stack {}

pub fn stack(factors: HashMap<String, MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  if factors.is_empty() {
    return Err(MFKDF2Error::InvalidDeriveParams("factors".to_string()));
  }

  Ok(MFKDF2Factor {
    id:          Some("stack".to_string()),
    factor_type: FactorType::Stack(Stack { factors, key: MFKDF2DerivedKey::default() }),
    salt:        [0u8; 32].to_vec(),
    entropy:     None,
  })
}
