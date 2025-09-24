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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::setup::factors::password::{PasswordOptions, password};

  #[tokio::test]
  async fn test_setup_stack_construction() {
    let factor1 =
      password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap();
    let factor2 =
      password("password456", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap();
    let factors = vec![factor1.clone(), factor2.clone()];

    let options =
      StackOptions { id: Some("my-stack".to_string()), threshold: Some(2), salt: None };

    let stack_factor = setup_stack(factors, options).await.unwrap();

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

  #[tokio::test]
  async fn test_setup_stack_empty_id() {
    let factor = password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap();
    let options =
      StackOptions { id: Some("".to_string()), threshold: None, salt: None };

    let result = setup_stack(vec![factor], options).await;
    assert!(matches!(result, Err(MFKDF2Error::MissingFactorId)));
  }

  #[tokio::test]
  async fn test_setup_stack_params_and_output() {
    let factor = password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap();
    let options =
      StackOptions { id: Some("my-stack".to_string()), threshold: Some(1), salt: None };

    let stack_factor = setup_stack(vec![factor], options).await.unwrap();
    let key = [0u8; 32];

    let params = stack_factor.factor_type.params_setup(key);
    let output = stack_factor.factor_type.output_setup(key);

    if let FactorType::Stack(stack) = stack_factor.factor_type {
      let expected_params = serde_json::to_value(&stack.key.policy).unwrap();
      let expected_output = serde_json::to_value(&stack.key).unwrap();
      assert_eq!(params, expected_params);
      assert_eq!(output, expected_output);
    } else {
      panic!("Expected Stack factor type");
    }
  }

  #[tokio::test]
  async fn test_setup_stack_no_factors() {
    let options =
      StackOptions { id: Some("my-stack".to_string()), threshold: Some(1), salt: None };

    let result = setup_stack(vec![], options).await;
    // This should fail inside key generation because there are no factors to build a policy from.
    assert!(result.is_err());
  }
}
