use crate::{definitions::MFKDF2Factor, error::MFKDF2Result, setup::factors::stack::StackOptions};

#[cfg(feature = "differential-test")]
/// Generates a deterministic stack ID based on the threshold and the sorted child factor IDs.
fn factor_id(n: u8, factors: &[MFKDF2Factor]) -> String {
  use sha2::{Digest, Sha256};
  // Deterministic stack id based on threshold and sorted child ids
  let mut child_ids: Vec<String> =
    factors.iter().map(|f| f.id.clone().unwrap_or_default()).collect();
  child_ids.sort();
  let seed = format!("{}:{}", n, child_ids.join(","));
  let mut hasher = Sha256::new();
  hasher.update(seed.as_bytes());
  let hash = hasher.finalize();
  format!("stack-{:x}", u64::from_be_bytes(<[u8; 8]>::try_from(&hash[..8]).unwrap()))
}

#[cfg(not(feature = "differential-test"))]
/// Generates a random ID for the given group of factors.
fn factor_id(_n: u8, _factors: &Vec<MFKDF2Factor>) -> String { uuid::Uuid::new_v4().to_string() }

/// Derives a key with threshold of 1 among n factors.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
///
/// use mfkdf2::{
///   derive::factors::password as derive_password,
///   policy::{PolicySetupOptions, at_least, derive, setup},
///   setup::factors::password::{PasswordOptions, password},
/// };
/// let f1 = password("password1", PasswordOptions { id: Some("pwd1".into()) })?;
/// let f2 = password("password2", PasswordOptions { id: Some("pwd2".into()) })?;
/// let f3 = password("password3", PasswordOptions { id: Some("pwd3".into()) })?;
/// // Create a stack factor such that any one factor is sufficient to derive the key.
/// let setup = setup(at_least(1, vec![f1, f2, f3])?, PolicySetupOptions::default())?;
///
/// // Derive the key using the stack factor.
/// let derived_key = derive(
///   &setup.policy,
///   &HashMap::from([("pwd1".to_string(), derive_password("password1")?)]),
///   None,
/// )?;
/// assert_eq!(derived_key.key, setup.key);
///
/// // Derive the key using other factors.
/// let derived_key = derive(
///   &derived_key.policy,
///   &HashMap::from([("pwd3".to_string(), derive_password("password3")?)]),
///   None,
/// );
/// assert_eq!(derived_key.key, setup.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_at_least"))]
pub fn at_least(n: u8, factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  let id = factor_id(n, &factors);
  let options = StackOptions { id: Some(id), threshold: Some(n), salt: None };
  crate::setup::factors::stack(factors, options)
}

/// Derives a key with threshold of 1 among 2 factors.
///
/// # Example
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::setup::factors::password::{password, PasswordOptions};
/// # use mfkdf2::derive::{factors::password as derive_password};
/// # use mfkdf2::policy::{or, setup, derive};
/// # use mfkdf2::policy::PolicySetupOptions;
/// let f1 = password("password1", PasswordOptions { id: Some("pwd1".into()) })?;
/// let f2 = password("password2", PasswordOptions { id: Some("pwd2".into()) })?;
///
/// let setup = setup(or(f1, f2)?, PolicySetupOptions::default())?;
///
/// // Derive the key using the stack factor.
/// let derived_key = derive(
///   &setup.policy,
///   &HashMap::from([("pwd1".to_string(), derive_password("password1")?)]),
///   None,
/// )?;
/// assert_eq!(derived_key.key, setup.key);
///
/// // Derive the key using invalid factors.
/// let derived_key = derive(
///   &derived_key.policy,
///   &HashMap::from([("pwd3".to_string(), derive_password("password3")?)]),
///   None,
/// );
/// assert!(derived_key.is_err());
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_or"))]
pub fn or(factor1: MFKDF2Factor, factor2: MFKDF2Factor) -> MFKDF2Result<MFKDF2Factor> {
  at_least(1, vec![factor1, factor2])
}

/// Derives a key with threshold of 2 among 2 factors.
///
/// # Example
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::setup::factors::password::{password, PasswordOptions};
/// # use mfkdf2::derive::{factors::password as derive_password};
/// # use mfkdf2::policy::{and, setup, derive};
/// # use mfkdf2::policy::PolicySetupOptions;
/// let f1 = password("password1", PasswordOptions { id: Some("pwd1".into()) })?;
/// let f2 = password("password2", PasswordOptions { id: Some("pwd2".into()) })?;
///
/// let setup = setup(and(f1, f2)?, PolicySetupOptions::default())?;
///
/// // Derive the key using the stack factor.
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
#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_and"))]
pub fn and(factor1: MFKDF2Factor, factor2: MFKDF2Factor) -> MFKDF2Result<MFKDF2Factor> {
  at_least(2, vec![factor1, factor2])
}

/// Derives a key with threshold of n among n factors.
///
/// # Example
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::setup::factors::password::{password, PasswordOptions};
/// # use mfkdf2::derive::{factors::password as derive_password};
/// # use mfkdf2::policy::{all, setup, derive};
/// # use mfkdf2::policy::PolicySetupOptions;
/// let f1 = password("password1", PasswordOptions { id: Some("pwd1".into()) })?;
/// let f2 = password("password2", PasswordOptions { id: Some("pwd2".into()) })?;
/// let f3 = password("password3", PasswordOptions { id: Some("pwd3".into()) })?;
///
/// let setup = setup(all(vec![f1, f2, f3])?, PolicySetupOptions::default())?;
///
/// // Derive the key using the stack factor.
/// let derived_key = derive(
///   &setup.policy,
///   &HashMap::from([
///     ("pwd1".to_string(), derive_password("password1")?),
///     ("pwd2".to_string(), derive_password("password2")?),
///     ("pwd3".to_string(), derive_password("password3")?),
///   ]),
///   None,
/// )?;
/// assert_eq!(derived_key.key, setup.key);
///
/// // Derive the key using invalid factors.
/// let derived_key = derive(
///   &derived_key.policy,
///   &HashMap::from([("pwd4".to_string(), derive_password("password4")?)]),
///   None,
/// );
/// assert!(derived_key.is_err());
///
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_all"))]
pub fn all(factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  assert!(factors.len() < 256, "Too many factors for policy");
  let n = factors.len() as u8;
  at_least(n, factors)
}

/// Derives a key with threshold of 1 among n factors.
///
/// # Example
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::setup::factors::password::{password, PasswordOptions};
/// # use mfkdf2::derive::{factors::password as derive_password};
/// # use mfkdf2::policy::{any, setup, derive};
/// # use mfkdf2::policy::PolicySetupOptions;
/// let f1 = password("password1", PasswordOptions { id: Some("pwd1".into()) })?;
/// let f2 = password("password2", PasswordOptions { id: Some("pwd2".into()) })?;
/// let f3 = password("password3", PasswordOptions { id: Some("pwd3".into()) })?;
///
/// let setup = setup(any(vec![f1, f2, f3])?, PolicySetupOptions::default())?;
///
/// // Derive the key using the stack factor.
/// let derive = derive(
///   &setup.policy,
///   &HashMap::from([("pwd1".to_string(), derive_password("password1")?)]),
///   None,
/// )?;
/// assert_eq!(derive.key, setup.key);
///
/// // Derive the key using any of the factors.
/// let derive = derive(
///   &setup.policy,
///   &HashMap::from([("pwd2".to_string(), derive_password("password2")?)]),
///   None,
/// )?;
/// assert_eq!(derive.key, setup.key);
///
/// // Derive the key using any of the factors.
/// let derive = derive(
///   &setup.policy,
///   &HashMap::from([("pwd3".to_string(), derive_password("password3")?)]),
///   None,
/// )?;
/// assert_eq!(derive.key, setup.key);
///
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_any"))]
pub fn any(factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> { at_least(1, factors) }
