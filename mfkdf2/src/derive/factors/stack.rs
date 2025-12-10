//! Stack factor derive
//!
//! This module implements the factor construction derive phase for the stack factor from
//! [`Stack`](`crate::setup::factors::stack()`). A stack factor treats an entire derived key (built
//! from one or more underlying factors) as a single higher‑level factor. During derive it accepts a
//! map of inner witnesses Wᵢⱼ, reconstructs the stacked key using [`crate::derive::key::key`] in
//! stack mode, and exposes the resulting policy and key material as a single factor
use std::collections::HashMap;

use crate::{
  definitions::{FactorType, Key, MFKDF2DerivedKey, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::stack::{Stack, StackOutput, StackParams},
};

impl FactorDerive for Stack {
  type Output = StackOutput;
  type Params = StackParams;

  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    // Stack factors don't need to include params during derivation
    // The key derivation is handled by the derive_key function
    self.key = crate::derive::key(&params.policy, self.factors.clone(), false, true)?;
    Ok(())
  }

  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> {
    Ok(StackParams {
      policy: self.key.policy.clone(),
    })
  }

  fn output(&self) -> Self::Output {
    StackOutput {
      key: self.key.clone(),
    }
  }
}

/// Factor construction derive phase for a stack factor
///
/// The `factors` map should contain witnesses used in the derive phase for the inner factors that
/// were used to construct the stacked key during setup, keyed by their factor ids. This helper
/// wraps them in a `Stack` factor that, when passed to [`KeyDerive`](`crate::derive::key::key`)
/// along with the appropriate policy, reconstructs the stacked key in stack mode.
///
/// # Errors
///
/// - [`MFKDF2Error::InvalidDeriveParams`] with `"factors"` when `factors` is empty
/// - [`MFKDF2Error::InvalidDeriveParams`] when the provided policy JSON cannot be deserialized into
///   a [`crate::policy::Policy`]
///
/// # Example
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   setup::{
/// #     self,
/// #     factors::{
/// #       password::{PasswordOptions, password as setup_password},
/// #       stack::{StackOptions, stack as setup_stack},
/// #     },
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive::factors::{password as derive_password, stack as derive_stack},
/// # };
/// let f1 = setup_password("password123", PasswordOptions { id: Some("pwd1".into()) })?;
/// let f2 = setup_password("password456", PasswordOptions { id: Some("pwd2".into()) })?;
/// let stack_factor = setup_stack(vec![f1, f2], StackOptions {
///   id:        Some("my-stack".into()),
///   threshold: Some(2),
///   salt:      None,
/// })?;
/// let setup_key = setup::key(&[stack_factor], MFKDF2Options::default())?;
///
/// let mut inner = HashMap::new();
/// inner.insert("pwd1".to_string(), derive_password("password123")?);
/// inner.insert("pwd2".to_string(), derive_password("password456")?);
/// let derive_stack_factor = derive_stack(inner)?;
///
/// let derived_key = mfkdf2::derive::key(
///   &setup_key.policy,
///   HashMap::from([("my-stack".to_string(), derive_stack_factor)]),
///   false,
///   false,
/// )?;
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
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

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_stack(factors: HashMap<String, MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  stack(factors)
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use super::*;
  use crate::{
    definitions::MFKDF2Options,
    derive::factors::password::password,
    setup::factors::{
      password::{PasswordOptions, password as setup_password},
      stack::{StackOptions, stack as setup_stack},
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

    crate::setup::key(&[stack_factor], MFKDF2Options::default())
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
      &setup_derived_key.policy,
      HashMap::from([("my-stack".to_string(), derive_stack_factor)]),
      true,
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
    let _derive_stack_factor =
      stack(HashMap::from([("pwd1".to_string(), password("p".to_string()).unwrap())])).unwrap();

    // Try to create invalid params - this will fail at deserialization
    let invalid_params_result: Result<StackParams, _> = serde_json::from_value(serde_json::json!("not a policy"));
    assert!(invalid_params_result.is_err());
  }
}
