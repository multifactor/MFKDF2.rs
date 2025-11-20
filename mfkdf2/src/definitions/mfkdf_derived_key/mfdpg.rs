//! Multi-factor deterministic password generator (MFDPG), which aims to rectify the shortcomings
//! of existing deterministic password generators (DPGs) by incorporating multi-factor key
//! derivation into the password management process.
//!
//! This module implements the MFDPG primitive on top of `MFKDF2DerivedKey` by sampling passwords
//! from a caller-provided regular language using deterministic randomness derived from the key.
//!
//! Generated passwords behave like a deterministic password manager: given the same multi-factor
//! setup, purpose string, salt, and policy regex, the derived password remains stable across
//! sessions, platforms, and bindings.
use rand::{SeedableRng, distributions::Distribution};
use rand_regex::Regex;

use crate::error::MFKDF2Error;

impl crate::definitions::MFKDF2DerivedKey {
  /// Derives a deterministic, policy-compliant password from an `MFKDF2DerivedKey`
  ///
  /// The password depends on the derived key material, an optional purpose string, an optional
  /// salt, and a caller-supplied regular expression that describes the allowed password language
  ///
  /// # Arguments
  ///
  /// * `purpose`: Optional logical namespace such as a domain, account identifier, or resource
  ///   label
  /// * `salt`: Optional opaque salt slice; changing this parameter changes the derived password
  ///   even under the same purpose
  /// * `regex`: Regular expression understood by `rand_regex` that constrains the generated
  ///   password shape
  ///
  /// # Examples
  ///
  /// The following example mirrors the MFDPG JavaScript helper where the same inputs produce the
  /// same password string
  ///
  /// ```rust
  /// # use mfkdf2::{error, setup, setup::factors::password::PasswordOptions};
  ///
  /// # fn main() -> Result<(), error::MFKDF2Error> {
  /// let setup_key = setup::key(
  ///   &[setup::factors::password("password1", PasswordOptions { id: Some("password1".to_owned()) })?],
  ///   setup::key::MFKDF2Options::default(),
  /// )?;
  ///
  /// let password = setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;
  ///
  /// let password2 =
  ///   setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;
  ///
  /// assert_eq!(password, password2);
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// # Determinism
  ///
  /// Repeated calls with the same key, purpose, salt, and regular expression always yield the same
  /// password
  ///
  /// # Panics
  ///
  /// This method panics when `regex` cannot be compiled by `rand_regex::Regex::compile`, for
  /// example when the pattern uses unsupported constructs or exceeds the configured DFA size
  /// bound (10 000 states)
  pub fn derive_password(
    &self,
    purpose: Option<&str>,
    salt: Option<&[u8]>,
    regex: &str,
  ) -> Result<String, MFKDF2Error> {
    let password_key = self.get_subkey(purpose, salt);
    // seed and rng with password_key
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(password_key);
    let dfa = Regex::compile(regex, 10000)?;
    Ok(dfa.sample(&mut rng))
  }
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_derive_password(
  derived_key: &crate::definitions::MFKDF2DerivedKey,
  purpose: Option<String>,
  salt: Option<Vec<u8>>,
  regex: &str,
) -> Result<String, MFKDF2Error> {
  let purpose = purpose.as_deref();
  let salt = salt.as_deref();
  derived_key.derive_password(purpose, salt, regex)
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use crate::{
    derive, error,
    setup::{self, factors::password::PasswordOptions},
  };

  #[test]
  fn basics_portability() -> Result<(), error::MFKDF2Error> {
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;

    let password =
      setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z0-9]{8}")?;
    assert!(password.len() > 5 && password.len() < 11);
    assert!(password.chars().all(|c| c.is_alphanumeric()));

    let password2 =
      setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z0-9]{8}")?;
    assert_eq!(password, password2);

    let derive_factors =
      HashMap::from([("password1".to_string(), derive::factors::password("password1")?)]);
    let derive_key = derive::key(&setup_key.policy, derive_factors, false, false)?;
    assert_eq!(derive_key.key, setup_key.key);

    let password3 =
      derive_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z0-9]{8}")?;
    assert_eq!(password, password3);

    Ok(())
  }

  #[test]
  fn basics_full_example() -> Result<(), error::MFKDF2Error> {
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;

    // Complex regex pattern: ([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*
    let password1 = setup_key.derive_password(
      Some("example.com"),
      Some(b"salt"),
      "([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*",
    )?;

    let derive_factors =
      HashMap::from([("password1".to_string(), derive::factors::password("password1")?)]);
    let derive_key = derive::key(&setup_key.policy, derive_factors, false, false)?;

    let password3 = derive_key.derive_password(
      Some("example.com"),
      Some(b"salt"),
      "([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*",
    )?;

    assert_eq!(password1, password3);
    Ok(())
  }

  #[test]
  fn correctness_basic_test() -> Result<(), error::MFKDF2Error> {
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;

    let password1 =
      setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    let password2 =
      setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    assert_eq!(password1, password2);
    assert!(password1.len() >= 6 && password1.len() <= 10);
    assert!(password1.chars().all(|c| c.is_alphabetic()));
    Ok(())
  }

  #[test]
  fn correctness_full_test() -> Result<(), error::MFKDF2Error> {
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;

    let password1 =
      setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    let derive_factors =
      HashMap::from([("password1".to_string(), derive::factors::password("password1")?)]);
    let derive_key = derive::key(&setup_key.policy, derive_factors, false, false)?;

    let password2 =
      derive_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    assert_eq!(password1, password2);
    assert!(password1.len() >= 6 && password1.len() <= 10);
    assert!(password1.chars().all(|c| c.is_alphabetic()));
    Ok(())
  }

  #[test]
  fn safety_basic_test() -> Result<(), error::MFKDF2Error> {
    let setup_key1 = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;
    let setup_key2 = setup::key(
      &[crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;

    let password1 =
      setup_key1.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    let password2 =
      setup_key2.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    // Different setups should produce different passwords
    assert_ne!(password1, password2);
    Ok(())
  }

  #[test]
  fn safety_full_test() -> Result<(), error::MFKDF2Error> {
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;

    let password1 =
      setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    let policy = setup_key.policy.clone();
    let derive_factors1 =
      HashMap::from([("password1".to_string(), derive::factors::password("password1")?)]);
    let derive_key1 = derive::key(&policy, derive_factors1, false, false)?;

    let password2 =
      derive_key1.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    // Same password should produce same result
    assert_eq!(password1, password2);

    let derive_factors2 =
      HashMap::from([("password1".to_string(), derive::factors::password("password2")?)]);
    let derive_key2 = derive::key(&policy, derive_factors2, false, false)?;

    let password3 =
      derive_key2.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    // Different password should produce different result
    assert_ne!(password1, password3);
    Ok(())
  }

  #[test]
  fn compatibility_basic_policy() -> Result<(), error::MFKDF2Error> {
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;

    let password =
      setup_key.derive_password(Some("example.com"), Some(b"salt"), "[a-zA-Z]{6,10}")?;

    // Verify password length is within expected range
    assert!(password.len() > 5, "Password length should be above 5, got {}", password.len());
    assert!(password.len() < 11, "Password length should be below 11, got {}", password.len());
    assert!(
      password.len() >= 6 && password.len() <= 10,
      "Password length should be between 6-10, got {}",
      password.len()
    );

    // Verify password contains only alphabetic characters
    assert!(
      password.chars().all(|c| c.is_alphabetic()),
      "Password should contain only alphabetic characters, got: {}",
      password
    );

    Ok(())
  }

  #[test]
  fn compatibility_custom_policy() -> Result<(), error::MFKDF2Error> {
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      setup::key::MFKDF2Options::default(),
    )?;

    // Complex regex pattern: ([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*
    let regex_pattern = "([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*";
    let password = setup_key.derive_password(Some("example.com"), Some(b"salt"), regex_pattern)?;

    // Verify password matches the complex regex pattern
    // The pattern requires either:
    // 1. One or more letters followed by a digit, then any alphanumeric characters
    // 2. One or more digits followed by a letter, then any alphanumeric characters
    let has_letter_then_digit = password.chars().enumerate().any(|(i, c)| {
      if i > 0 && c.is_ascii_digit() {
        password[..i].chars().any(|prev_c| prev_c.is_ascii_alphabetic())
      } else {
        false
      }
    });

    let has_digit_then_letter = password.chars().enumerate().any(|(i, c)| {
      if i > 0 && c.is_ascii_alphabetic() {
        password[..i].chars().any(|prev_c| prev_c.is_ascii_digit())
      } else {
        false
      }
    });

    assert!(
      has_letter_then_digit || has_digit_then_letter,
      "Password should match pattern ([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*, got: {}",
      password
    );

    // Verify all characters are alphanumeric
    assert!(
      password.chars().all(|c| c.is_alphanumeric()),
      "Password should contain only alphanumeric characters, got: {}",
      password
    );

    Ok(())
  }
}
