//! Password-based factor setup.
//!
//! This factor turns a user-chosen password into MFKDF2 factor material. The factor also records
//! an entropy estimate derived from Dropbox's [`mod@zxcvbn`] crate, which can be used to enforce
//! password strength policies.
use serde::{Deserialize, Serialize};
use zxcvbn::zxcvbn;

use crate::{
  defaults::password as password_defaults,
  definitions::{FactorType, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::FactorSetup,
  traits::Factor,
};

/// Password factor state
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
pub struct Password {
  /// User-chosen password string.
  pub password: String,
}

impl Factor for Password {
  type Output = PasswordOutput;
  type Params = PasswordParams;

  fn kind(&self) -> &'static str { "password" }

  fn bytes(&self) -> Vec<u8> { self.password.as_bytes().to_vec() }
}

/// Password factor parameters.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct PasswordParams {}

/// Password factor output.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct PasswordOutput {
  /// Password strength estimate from zxcvbn.
  pub strength: serde_json::Value,
}

impl FactorSetup for Password {
  fn params(&self, _key: crate::definitions::Key) -> MFKDF2Result<Self::Params> {
    Ok(PasswordParams::default())
  }

  fn output(&self) -> Self::Output {
    PasswordOutput { strength: serde_json::to_value(zxcvbn(&self.password, &[])).unwrap() }
  }
}

/// Options for setting up a password factor.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PasswordOptions {
  /// Optional application-defined identifier for the factor. Defaults to `"password"`. If
  /// provided, it must be non-empty.
  pub id: Option<String>,
}

/// Creates a password factor.
///
/// This helper normalizes and validates the password, computes its entropy using
/// `zxcvbn`, and wraps it in an [`MFKDF2Factor`]. The resulting factor can be used
/// directly in `setup_stack` or in single-factor keys.
///
/// # Errors
/// - [`MFKDF2Error::PasswordEmpty`] if `password` is empty.
/// - [`MFKDF2Error::MissingFactorId`] if `options.id` is present but empty.
///
/// # Examples
///
/// Basic usage with a default id:
///
/// ```rust
/// # use mfkdf2::setup::factors::password::{password, PasswordOptions};
/// let factor = password("correct horse battery staple", PasswordOptions::default())?;
/// assert_eq!(factor.id.as_deref(), Some("password"));
/// assert!(factor.entropy.unwrap() > 40.0);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// Using a custom id so you can distinguish multiple password factors:
///
/// ```rust
/// # use mfkdf2::setup::factors::password::{password, PasswordOptions};
/// let options = PasswordOptions { id: Some("login-password".to_string()) };
/// let factor = password("my login secret", options)?;
/// assert_eq!(factor.id.as_deref(), Some("login-password"));
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn password(
  password: impl Into<String>,
  options: PasswordOptions,
) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }

  let password = password.into();
  if password.is_empty() {
    return Err(MFKDF2Error::PasswordEmpty);
  }
  let strength = zxcvbn(&password, &[]);

  Ok(MFKDF2Factor {
    id:          Some(options.id.unwrap_or_else(|| password_defaults::ID.to_string())),
    factor_type: FactorType::Password(Password { password }),
    entropy:     Some((strength.guesses() as f64).log2()),
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn setup_password(password: String, options: PasswordOptions) -> MFKDF2Result<MFKDF2Factor> {
  crate::setup::factors::password::password(password, options)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{error::MFKDF2Error, setup::FactorSetup};

  #[test]
  fn password_strength() {
    let factor = password("password", PasswordOptions { id: None }).unwrap();
    assert_eq!(factor.entropy.unwrap().floor(), 1.0);

    let factor =
      password("98p23uijafjj--ah77yhfraklhjaza!?a3", PasswordOptions { id: None }).unwrap();
    assert_eq!(factor.entropy, Some(64.0));
  }

  #[test]
  fn password_empty() {
    let err = password("", PasswordOptions { id: None }).unwrap_err();
    assert!(matches!(err, MFKDF2Error::PasswordEmpty));
  }

  #[test]
  fn password_empty_id() {
    let err = password("password", PasswordOptions { id: Some("".to_string()) }).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingFactorId));
  }

  #[test]
  fn password_valid() {
    let factor = password("hello", PasswordOptions { id: None }).unwrap();
    assert_eq!(factor.id, Some("password".to_string()));
    let p = match &factor.factor_type {
      FactorType::Password(p) => p,
      _ => panic!("Wrong factor type"),
    };
    assert_eq!(p.password, "hello");
    assert_eq!(p.bytes(), "hello".as_bytes());
    let params = p.params([0; 32].into()).unwrap();
    assert_eq!(params, PasswordParams::default());
  }
}
