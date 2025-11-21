use serde::{Deserialize, Serialize};

use crate::{
  definitions::{MFKDF2DerivedKey, MFKDF2Factor, MFKDF2Options, Salt},
  error::{MFKDF2Error, MFKDF2Result},
  setup::key as setup_key,
};

/// Options for setting up a policy.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicySetupOptions {
  /// Unique identifier for the policy.
  pub id:        Option<String>,
  /// Threshold for the policy.
  pub threshold: Option<u8>,
  /// Flag to perform integrity checks for the policy.
  pub integrity: Option<bool>,
  /// 32 byte salt value used to derive the policy key.
  pub salt:      Option<Salt>,
}

impl From<PolicySetupOptions> for MFKDF2Options {
  fn from(value: PolicySetupOptions) -> Self {
    let PolicySetupOptions { id, threshold, integrity, salt } = value;

    let mut options = MFKDF2Options::default();

    if let Some(id) = id {
      options.id = Some(id);
    }

    options.threshold = threshold;

    if let Some(integrity) = integrity {
      options.integrity = Some(integrity);
    }

    if let Some(salt) = salt {
      options.salt = Some(salt);
    }

    options
  }
}

/// Policy factor construction. Validates and setup a policy based multi-factor derived key.
///
/// # Arguments
///
/// * `factor`: [`MFKDF2Factor`] construction. Usually setup using policy combinators
///   ([`and`](`crate::policy::and`), [`or`](`crate::policy::or`), [`all`](`crate::policy::all`),
///   [`any`](`crate::policy::any`)).
/// * `options`: [`PolicySetupOptions`] to use for the setup.
///
/// # Example
///
/// ```rust
/// # use std::collections::HashMap;
/// use mfkdf2::{
///   derive::factors::password as derive_password,
///   policy::{PolicySetupOptions, and, derive, or, setup},
///   setup::factors::password::{PasswordOptions, password},
/// };
/// let setup = setup(
///   and(
///     password("password1", PasswordOptions { id: Some("pwd1".into()) })?,
///     or(
///       password("password2", PasswordOptions { id: Some("pwd2".into()) })?,
///       password("password3", PasswordOptions { id: Some("pwd3".into()) })?,
///     )?,
///   )?,
///   PolicySetupOptions::default(),
/// )?;
///
/// // Derive the key using the policy.
/// let derived_key = derive(
///   &setup.policy,
///   &HashMap::from([
///     ("pwd1".to_string(), derive_password("password1")?),
///     ("pwd2".to_string(), derive_password("password2")?),
///   ]),
///   None,
/// )?;
/// assert_eq!(derived_key.key, setup.key);
///
/// // Derive the key using invalid factors.
/// let derived_key = derive(
///   &setup.policy,
///   &HashMap::from([("pwd3".to_string(), derive_password("password3")?)]),
///   None,
/// );
/// assert!(derived_key.is_err());
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn setup(factor: MFKDF2Factor, options: PolicySetupOptions) -> MFKDF2Result<MFKDF2DerivedKey> {
  let derived_key = setup_key(&[factor], options.into())?;

  if !derived_key.policy.validate() {
    return Err(MFKDF2Error::DuplicateFactorId);
  }

  Ok(derived_key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn policy_setup(
  factor: MFKDF2Factor,
  options: PolicySetupOptions,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  setup(factor, options)
}
