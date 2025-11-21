//! Derive phase [Password](`crate::setup::factors::password`) construction. Takes a
//! user‑supplied password answer and computes an [`MFKDF2Factor`] witness Wᵢⱼ.
use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  definitions::{FactorType, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::password::Password,
};

impl FactorDerive for Password {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, _params: Self::Params) -> MFKDF2Result<()> { Ok(()) }

  fn output(&self) -> Self::Output { json!({"strength": zxcvbn(&self.password, &[])}) }
}

/// Factor construction derive phase
///
/// Derives a password factor from a string. Validates the password and returns an [`MFKDF2Factor`]
/// suitable for use with [`crate::derive::key`]. Unlike setup, the factor constructed for the
/// derive phase does not assign an id or entropy estimate. Those are recovered from the policy
/// during derivation
///
/// # Errors
///
/// - [`MFKDF2Error::PasswordEmpty`] if `password` is empty
///
/// # Example
///
/// Single‑factor setup/derive using the password factor within KeySetup/KeyDerive:
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   setup::{
/// #     self,
/// #     factors::password::{PasswordOptions, password as setup_password},
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive,
/// #   derive::factors::password as derive_password,
/// # };
/// #
/// # fn main() -> MFKDF2Result<()> {
/// let setup_factor = setup_password("correct horse battery staple", PasswordOptions::default())?;
/// let setup_key = setup::key(&[setup_factor], MFKDF2Options::default())?;
///
/// let derive_factor = derive_password("correct horse battery staple")?;
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("password".to_string(), derive_factor)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok(())
/// # }
/// ```
pub fn password(password: impl Into<String>) -> MFKDF2Result<MFKDF2Factor> {
  let password = std::convert::Into::<String>::into(password);
  if password.is_empty() {
    return Err(MFKDF2Error::PasswordEmpty);
  }

  Ok(MFKDF2Factor {
    factor_type: FactorType::Password(Password { password }),
    entropy:     None,
    id:          None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_password(password: String) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::password::password(password)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{error::MFKDF2Error, setup::FactorSetup};

  #[test]
  fn test_password_empty() {
    let err = password("").unwrap_err();
    assert!(matches!(err, MFKDF2Error::PasswordEmpty));
  }

  #[test]
  fn test_password_valid() {
    let factor = password("hello").unwrap();
    assert_eq!(factor.id, None);

    match &factor.factor_type {
      FactorType::Password(p) => {
        assert_eq!(p.password, "hello");
        assert_eq!(factor.data(), "hello".as_bytes());
        let params: Value = <Password as FactorSetup>::params(p, [0u8; 32].into()).unwrap();

        assert_eq!(params, json!({}));
      },
      _ => panic!("Wrong factor type"),
    }
  }
}
