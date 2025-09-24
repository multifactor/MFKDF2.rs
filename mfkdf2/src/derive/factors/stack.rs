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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive::factors::password::derive_password,
        setup::factors::{
            password::{password as setup_password, PasswordOptions},
            stack::{setup_stack, StackOptions},
            FactorSetup,
        },
    };
    use std::collections::HashMap;

    async fn setup_test_stack() -> (MFKDF2Factor, Value) {
        let factor1 =
            setup_password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap();
        let factor2 =
            setup_password("password456", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap();
        let factors = vec![factor1, factor2];

        let options = StackOptions {
            id: Some("my-stack".to_string()),
            threshold: Some(2),
            salt: None,
        };

        let stack_factor = setup_stack(factors, options).await.unwrap();
        let params = stack_factor.factor_type.params_setup([0; 32]);
        (stack_factor, params)
    }

    #[tokio::test]
    async fn test_derive_stack_round_trip() {
        let (setup_stack_factor, setup_params) = setup_test_stack().await;

        let derive_factor1 = derive_password("password123".to_string()).unwrap();
        let derive_factor2 = derive_password("password456".to_string()).unwrap();

        let mut derive_factors = HashMap::new();
        derive_factors.insert("pwd1".to_string(), derive_factor1);
        derive_factors.insert("pwd2".to_string(), derive_factor2);

        let mut derive_stack_factor = stack(derive_factors).unwrap();

        let result = derive_stack_factor.factor_type.include_params(setup_params);
        assert!(result.is_ok());

        if let FactorType::Stack(setup_stack) = setup_stack_factor.factor_type {
            if let FactorType::Stack(derive_stack) = derive_stack_factor.factor_type {
                assert_eq!(derive_stack.key.key, setup_stack.key.key);
                assert_eq!(
                    serde_json::to_string(&derive_stack.key.policy).unwrap(),
                    serde_json::to_string(&setup_stack.key.policy).unwrap()
                );
            } else {
                panic!("Expected derive Stack factor type");
            }
        } else {
            panic!("Expected setup Stack factor type");
        }
    }

    #[test]
    fn test_derive_stack_empty_factors() {
        let factors = HashMap::new();
        let result = stack(factors);
        assert!(matches!(
            result,
            Err(MFKDF2Error::InvalidDeriveParams(s)) if s == "factors"
        ));
    }

    #[tokio::test]
    async fn test_derive_stack_invalid_params() {
        let mut derive_stack_factor = stack(HashMap::from([(
            "pwd1".to_string(),
            derive_password("p".to_string()).unwrap(),
        )]))
        .unwrap();

        let invalid_params = json!("not a policy");
        let result = derive_stack_factor.factor_type.include_params(invalid_params);
        assert!(matches!(
            result,
            Err(MFKDF2Error::InvalidDeriveParams(s)) if s == "params"
        ));
    }

    #[tokio::test]
    async fn test_derive_stack_params_and_output() {
        let (_setup_stack_factor, setup_params) = setup_test_stack().await;

        let mut derive_factors = HashMap::new();
        derive_factors.insert(
            "pwd1".to_string(),
            derive_password("password123".to_string()).unwrap(),
        );
        derive_factors.insert(
            "pwd2".to_string(),
            derive_password("password456".to_string()).unwrap(),
        );

        let mut derive_stack_factor = stack(derive_factors).unwrap();
        derive_stack_factor.factor_type.include_params(setup_params).unwrap();

        let params_derive = derive_stack_factor.factor_type.params_derive([0; 32]);
        let output_derive = derive_stack_factor.factor_type.output_derive();

        if let FactorType::Stack(stack) = derive_stack_factor.factor_type {
            let expected_params = serde_json::to_value(&stack.key.policy).unwrap();
            let expected_output = serde_json::to_value(&stack.key).unwrap();
            assert_eq!(params_derive, expected_params);
            assert_eq!(output_derive, expected_output);
        } else {
            panic!("Expected Stack factor type");
        }
    }
}
