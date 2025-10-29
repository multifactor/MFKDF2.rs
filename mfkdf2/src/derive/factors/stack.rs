use std::collections::HashMap;

use serde_json::{Value, json};

use crate::{
  definitions::{FactorType, Key, MFKDF2DerivedKey, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  policy::Policy,
  setup::factors::stack::Stack,
};

impl FactorDerive for Stack {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    // Stack factors don't need to include params during derivation
    // The key derivation is handled by the derive_key function
    let policy: Policy = serde_json::from_value(params)
      .map_err(|_| MFKDF2Error::InvalidDeriveParams("params".to_string()))?;
    self.key = crate::derive::key(policy, self.factors.clone(), false, true)?;
    Ok(())
  }

  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> {
    serde_json::to_value(&self.key.policy)
      .map_err(|_| MFKDF2Error::InvalidDeriveParams("policy".to_string()))
  }

  fn output(&self) -> Self::Output { serde_json::to_value(&self.key).unwrap_or(json!({})) }
}

pub fn stack(factors: HashMap<String, MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  if factors.is_empty() {
    return Err(MFKDF2Error::InvalidDeriveParams("factors".to_string()));
  }

  Ok(MFKDF2Factor {
    id:          Some("stack".to_string()),
    factor_type: FactorType::Stack(Stack { factors, key: MFKDF2DerivedKey::default() }),
    entropy:     None,
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn derive_stack(factors: HashMap<String, MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  stack(factors)
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use super::*;
  use crate::{
    derive::factors::password::password,
    setup::{
      factors::{
        password::{PasswordOptions, password as setup_password},
        stack::{StackOptions, stack as setup_stack},
      },
      key::MFKDF2Options,
    },
  };

  fn setup_test_stack() -> MFKDF2DerivedKey {
    let factor1 =
      setup_password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap();
    let factor2 =
      setup_password("password456", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap();
    let factors = vec![factor1, factor2];

    let options =
      StackOptions { id: Some("my-stack".to_string()), threshold: Some(2), salt: None };

    let stack_factor = setup_stack(factors, options).unwrap();
    // let params = stack_factor.factor_type.params_setup([0; 32]);

    crate::setup::key(vec![stack_factor], MFKDF2Options::default())
      .expect("derived key should be created")
  }

  #[test]
  fn derive_stack_round_trip() {
    let setup_derived_key = setup_test_stack();

    let derive_factor1 = password("password123".to_string()).unwrap();
    let derive_factor2 = password("password456".to_string()).unwrap();

    let mut derive_factors = HashMap::new();
    derive_factors.insert("pwd1".to_string(), derive_factor1);
    derive_factors.insert("pwd2".to_string(), derive_factor2);

    let derive_stack_factor = stack(derive_factors).unwrap();

    let derive_key = crate::derive::key(
      setup_derived_key.policy,
      HashMap::from([("my-stack".to_string(), derive_stack_factor)]),
      false,
      false,
    );
    assert!(derive_key.is_ok());
    let derive_key = derive_key.unwrap();

    assert_eq!(setup_derived_key.key, derive_key.key);
  }

  #[test]
  fn derive_stack_empty_factors() {
    let factors = HashMap::new();
    let result = stack(factors);
    assert!(matches!(
        result,
        Err(MFKDF2Error::InvalidDeriveParams(s)) if s == "factors"
    ));
  }

  #[test]
  fn derive_stack_invalid_params() {
    let mut derive_stack_factor =
      stack(HashMap::from([("pwd1".to_string(), password("p".to_string()).unwrap())])).unwrap();

    let invalid_params = json!("not a policy");
    let result = derive_stack_factor.factor_type.include_params(invalid_params);
    assert!(matches!(
        result,
        Err(MFKDF2Error::InvalidDeriveParams(s)) if s == "params"
    ));
  }
}
