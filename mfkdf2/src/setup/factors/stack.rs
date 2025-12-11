//! Stack factor setup
//!
//! A stack factor wraps an entire MFKDF2 key (built from one or more underlying factors) as a
//! **single reusable factor**. This is useful when you want to derive a key once from a complex
//! policy and then treat that key as another factor in a higher‑level policy or protocol.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
  definitions::{
    FactorType, Key, MFKDF2DerivedKey, MFKDF2Factor, MFKDF2Options, Salt, factor::FactorMetadata,
  },
  error::{MFKDF2Error, MFKDF2Result},
  policy::Policy,
  setup::{FactorSetup, key},
};

/// Options for constructing a stack factor.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StackOptions {
  /// Optional application-defined identifier for the factor. Defaults to `"stack"`. If
  /// provided, it must be non-empty
  pub id:        Option<String>,
  /// Number of underlying factors that must be present to derive the stacked key
  pub threshold: Option<u8>,
  /// Optional override for the policy salt. If not provided, a random salt will be generated.
  pub salt:      Option<Salt>,
}

impl From<StackOptions> for MFKDF2Options {
  fn from(mut value: StackOptions) -> Self {
    MFKDF2Options {
      id:        value.id.take(),
      threshold: value.threshold.take(),
      salt:      value.salt.take(),
      stack:     Some(true),
      integrity: Some(false),
      time:      None,
      memory:    None,
    }
  }
}

/// Stack factor state.
///
/// Contains both the derived key and a map of the underlying factors keyed by
/// their ids. The factor bytes are the derived key material.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stack {
  /// Map of underlying factors keyed by their ids.
  pub factors: HashMap<String, MFKDF2Factor>,
  /// Final Derived key.
  pub key:     MFKDF2DerivedKey,
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Stack {
  fn zeroize(&mut self) {
    self.factors.values_mut().for_each(zeroize::Zeroize::zeroize);
    self.key.zeroize();
  }
}

impl FactorMetadata for Stack {
  fn kind(&self) -> String { "stack".to_string() }

  fn bytes(&self) -> Vec<u8> { self.key.key.clone().into() }
}

/// Stack factor parameters.
pub type StackParams = Policy;

/// Stack factor output.
pub type StackOutput = MFKDF2DerivedKey;

impl FactorSetup for Stack {
  type Output = StackOutput;
  type Params = StackParams;

  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> { Ok(self.key.policy.clone()) }

  fn output(&self) -> Self::Output { self.key.clone() }
}

/// Creates a stack factor from existing factors.
///
/// Internally this calls [`key::key`] to build an `MFKDF2DerivedKey` over the
/// provided factors and then packages the result as a single [`MFKDF2Factor`].
/// This can fail if the inputs cannot form a valid policy (for example, an empty
/// factor list or an impossible threshold).
///
/// # Errors
/// - [`MFKDF2Error::MissingFactorId`] if `id` is provided but empty.
/// - Any error returned by [`key::key`] when building the underlying policy.
///
/// # Example
///
/// ```rust
/// # use mfkdf2::setup::factors::password::{password, PasswordOptions};
/// # use mfkdf2::setup::factors::stack::{stack, StackOptions};
/// let f1 = password("password1", PasswordOptions { id: Some("pwd1".into()) })?;
/// let f2 = password("password2", PasswordOptions { id: Some("pwd2".into()) })?;
/// let stacked = stack(vec![f1, f2], StackOptions {
///   id:        Some("my-stack".into()),
///   threshold: Some(2),
///   salt:      None,
/// })?;
/// assert_eq!(stacked.id.as_deref(), Some("my-stack"));
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
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

  let key = key::key(&factors, options.into())?;

  let mut factor_map = HashMap::new();
  for factor in factors {
    factor_map.insert(factor.id.clone().unwrap(), factor);
  }

  let real_entropy = key.entropy.real;

  Ok(MFKDF2Factor {
    id,
    factor_type: FactorType::Stack(Stack { factors: factor_map, key }),
    entropy: Some(real_entropy),
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn setup_stack(
  factors: Vec<MFKDF2Factor>,
  options: StackOptions,
) -> MFKDF2Result<MFKDF2Factor> {
  stack(factors, options)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    definitions::factor::FactorParams,
    setup::factors::password::{PasswordOptions, password},
  };

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

    let params = stack_factor.factor_type.setup().params(key.into()).unwrap();
    let output = stack_factor.factor_type.setup().output();

    if let FactorType::Stack(stack) = stack_factor.factor_type {
      assert_eq!(params, FactorParams::Stack(stack.key.policy.clone()));
      assert_eq!(output, serde_json::to_value(stack.key).unwrap());
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
