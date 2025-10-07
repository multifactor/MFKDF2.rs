use std::collections::HashMap;

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  definitions::{
    factor::{FactorMetadata, FactorType, MFKDF2Factor},
    key::Key,
    mfkdf_derived_key::MFKDF2DerivedKey,
  },
  error::{MFKDF2Error, MFKDF2Result},
  setup::{
    FactorSetup,
    key::{self, MFKDF2Options},
  },
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StackOptions {
  pub id:        Option<String>,
  pub threshold: Option<u8>,
  pub salt:      Option<Vec<u8>>,
}

impl From<StackOptions> for MFKDF2Options {
  fn from(value: StackOptions) -> Self {
    let StackOptions { id, threshold, salt } = value;

    MFKDF2Options {
      id,
      threshold,
      salt,
      stack: Some(true),
      integrity: Some(false),
      time: None,
      memory: None,
    }
  }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stack {
  pub factors: HashMap<String, MFKDF2Factor>,
  pub key:     MFKDF2DerivedKey,
}

impl FactorMetadata for Stack {
  fn kind(&self) -> String { "stack".to_string() }
}

impl FactorSetup for Stack {
  fn bytes(&self) -> Vec<u8> { self.key.key.clone() }

  fn params(&self, _key: Key) -> Value {
    serde_json::to_value(&self.key.policy).unwrap_or(json!({}))
  }

  fn output(&self, _key: Key) -> Value { serde_json::to_value(&self.key).unwrap_or(json!({})) }
}

pub fn stack(factors: Vec<MFKDF2Factor>, options: StackOptions) -> MFKDF2Result<MFKDF2Factor> {
  let id = match options.id {
    None => Some("stack".to_string()),
    Some(ref id) => {
      if id.is_empty() {
        return Err(MFKDF2Error::MissingFactorId);
      }
      Some(id.clone())
    },
  };

  let key = key::key(factors.clone(), options.into())?;

  // per-factor salt
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  let mut factor_map = HashMap::new();
  factors.into_iter().for_each(|f| {
    factor_map.insert(f.id.clone().unwrap(), f);
  });

  Ok(MFKDF2Factor {
    id,
    factor_type: FactorType::Stack(Stack { factors: factor_map, key: key.clone() }),
    salt: salt.to_vec(),
    entropy: Some(key.entropy.real as f64),
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn setup_stack(
  factors: Vec<MFKDF2Factor>,
  options: StackOptions,
) -> MFKDF2Result<MFKDF2Factor> {
  stack(factors, options)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::setup::factors::password::{PasswordOptions, password};

  #[test]
  fn setup_stack_construction() {
    let factor1 =
      password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap();
    let factor2 =
      password("password456", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap();
    let factors = vec![factor1.clone(), factor2.clone()];

    let options =
      StackOptions { id: Some("my-stack".to_string()), threshold: Some(2), salt: None };

    let stack_factor = stack(factors, options).unwrap();

    assert_eq!(stack_factor.id.as_deref(), Some("my-stack"));
    assert_eq!(stack_factor.kind(), "stack");

    if let FactorType::Stack(stack) = stack_factor.factor_type {
      assert_eq!(stack.factors.len(), 2);
      assert!(stack.factors.contains_key("pwd1"));
      assert!(stack.factors.contains_key("pwd2"));
      assert!(!stack.key.key.is_empty());
      assert_eq!(stack.key.policy.threshold, 2);
    } else {
      panic!("Expected Stack factor type");
    }
  }

  #[test]
  fn test_setup_stack_empty_id() {
    let factor = password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap();
    let options =
      StackOptions { id: Some("".to_string()), threshold: None, salt: None };

    let result = stack(vec![factor], options);
    assert!(matches!(result, Err(MFKDF2Error::MissingFactorId)));
  }

  #[test]
  fn setup_stack_params_and_output() {
    let factor = password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap();
    let options =
      StackOptions { id: Some("my-stack".to_string()), threshold: Some(1), salt: None };

    let stack_factor = stack(vec![factor], options).unwrap();
    let key = [0u8; 32];

    let params = stack_factor.factor_type.setup().params(key.into());
    let output = stack_factor.factor_type.output(key.into());

    if let FactorType::Stack(stack) = stack_factor.factor_type {
      let expected_params = serde_json::to_value(&stack.key.policy).unwrap();
      let expected_output = serde_json::to_value(&stack.key).unwrap();
      assert_eq!(params, expected_params);
      assert_eq!(output, expected_output);
    } else {
      panic!("Expected Stack factor type");
    }
  }

  #[test]
  fn setup_stack_no_factors() {
    let options =
      StackOptions { id: Some("my-stack".to_string()), threshold: Some(1), salt: None };

    let result = stack(vec![], options);
    // This should fail inside key generation because there are no factors to build a policy from.
    assert!(result.is_err());
  }
}
