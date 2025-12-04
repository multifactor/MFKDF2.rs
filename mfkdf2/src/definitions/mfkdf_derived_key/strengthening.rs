use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose};

use crate::{crypto::encrypt, definitions::MFKDF2DerivedKey, error::MFKDF2Result};

impl MFKDF2DerivedKey {
  /// Increase the Argon2 work factor for an already derived key **without** changing the key.
  ///
  /// Strengthening is useful when you want to upgrade the KDF parameters over time (e.g. as
  /// hardware gets faster) but you cannot afford to re-encrypt all application data. The
  /// [`MFKDF2DerivedKey`] already contains the user-derived key and an authenticated copy of
  /// the public policy; calling this method:
  ///
  /// - derives a new key-encapsulation key (KEK) from `self.secret` and the policy salt using
  ///   stronger Argon2 parameters, and
  /// - re-encrypts the policy key with that KEK and updates `policy.time` / `policy.memory`.
  ///
  /// Clients should persist the updated `policy` back to their storage (e.g. user database)
  /// and discard the old one. Any attempt to reuse or roll back the previous policy will fail
  /// the integrity check during the next derive
  /// [`MFKDF2Error::PolicyIntegrityCheckFailed`](`crate::error::MFKDF2Error::PolicyIntegrityCheckFailed`),
  /// ensuring that only a user who can compute the correct key can authorize an increase in cost.
  ///
  /// The `time` and `memory` arguments are additive deltas over the library defaults used at
  /// setup time. Internally they are applied as `DEFAULT_T_COST + time` and
  /// `DEFAULT_M_COST + memory`, which allows you to express "make this policy 3 steps slower
  /// and 16 MiB more memory hungry than it was originally", rather than hard-coding
  /// absolute Argon2 parameters.
  ///
  /// # Example
  ///
  /// ```rust
  /// use std::collections::HashMap;
  /// use mfkdf2::{
  ///   derive,
  ///   derive::factors as derive_factors,
  ///   error::MFKDF2Error,
  ///   setup::{
  ///     self,
  ///     factors::password::PasswordOptions,
  ///   },
  ///   definitions::MFKDF2Options,
  /// };
  ///
  /// // 1. Create a simple single-password policy
  /// let setup_factors = vec![
  ///   setup::factors::password("password1", PasswordOptions::default())?,
  /// ];
  ///
  /// let setup_key =
  ///   setup::key(&setup_factors, MFKDF2Options::default())?;
  ///
  /// // 2. User logs in with the same password and we derive the current key.
  /// let mut derived_key = derive::key(
  ///   &setup_key.policy,
  ///   HashMap::from([(
  ///     "password".to_string(),
  ///     derive_factors::password("password1").expect("Failed to derive password factor"),
  ///   )]),
  ///   true, // use integrity check
  ///   false, // use stack key
  /// )?;
  ///
  /// // 3. bump the Argon2 time and memory costs. These values are *deltas* over the defaults from setup.
  /// derived_key.strengthen(3, 16 * 1024)?;
  ///
  /// // 4. Persist `derived_key.policy` as the new policy for this user.
  /// //    Future derives must use the strengthened policy.
  /// let derived_key2 = derive::key(
  ///   &derived_key.policy,
  ///   HashMap::from([(
  ///     "password".to_string(),
  ///     derive_factors::password("password1")?,
  ///   )]),
  ///   true,
  ///   false,
  /// )?;
  ///
  /// assert_eq!(derived_key2.key, setup_key.key);
  /// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
  /// ```
  ///
  /// # Errors
  ///
  /// This function returns an [`MFKDF2Result`] whose error is typically:
  ///
  /// - [`crate::error::MFKDF2Error::Argon2`] if the chosen `time` / `memory` values cannot be
  ///   represented as valid Argon2 parameters.
  /// - [`crate::error::MFKDF2Error::Base64Decode`] if the policy salt has been corrupted or
  ///   tampered with and can no longer be base64-decoded.
  ///
  /// Note that downstream operations that use the upgraded policy may return
  /// [`crate::error::MFKDF2Error::PolicyIntegrityCheckFailed`] if an attacker attempts to
  /// weaken or roll back the policy, as that invalidates the integrity MAC.
  pub fn strengthen(&mut self, time: u32, memory: u32) -> MFKDF2Result<()> {
    // derive internal key
    let internal_key = self.derive_internal_key()?;

    // update policy time and memory
    self.policy.time = time;
    self.policy.memory = memory;

    let mut kek = [0u8; 32];

    let salt = general_purpose::STANDARD.decode(&self.policy.salt).unwrap();

    Argon2::new(
      argon2::Algorithm::Argon2id,
      Version::default(),
      Params::new(
        argon2::Params::DEFAULT_M_COST + memory,
        argon2::Params::DEFAULT_T_COST + time,
        1,
        Some(32),
      )?,
    )
    .hash_password_into(&self.secret, &salt, &mut kek)?;

    let policy_key = encrypt(&internal_key, &kek);
    self.policy.key = general_purpose::STANDARD.encode(policy_key);
    Ok(())
  }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_strengthen(
  derived_key: MFKDF2DerivedKey,
  time: u32,
  memory: u32,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.strengthen(time, memory)?;
  Ok(derived_key)
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use crate::{
    definitions::MFKDF2Options,
    derive,
    derive::factors as derive_factors,
    error,
    setup::{self, factors::password::PasswordOptions},
  };

  #[test]
  fn strengthen_time() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![crate::setup::factors::password("password1", PasswordOptions {
      id: Some("password1".to_string()),
    })?];

    let setup_key = setup::key(&setup_factors, MFKDF2Options::default())?;

    assert_eq!(setup_key.policy.time, 0);

    let mut derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key.policy.time, 0);
    assert_eq!(derive_key.key, setup_key.key);

    derive_key.strengthen(5, 0)?;

    assert_eq!(derive_key.policy.time, 5);
    assert_eq!(derive_key.policy.memory, 0);

    let derive_key2 = derive::key(
      &derive_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key2.policy.time, 5);
    assert_eq!(derive_key2.policy.memory, 0);
    assert_eq!(derive_key2.key, derive_key.key);

    Ok(())
  }

  #[test]
  fn strengthen_memory() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![crate::setup::factors::password("password1", PasswordOptions {
      id: Some("password1".to_string()),
    })?];

    let setup_key = setup::key(&setup_factors, MFKDF2Options::default())?;

    assert_eq!(setup_key.policy.memory, 0);

    let mut derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key.policy.memory, 0);

    derive_key.strengthen(0, 32768)?;

    assert_eq!(derive_key.policy.time, 0);
    assert_eq!(derive_key.policy.memory, 32768);

    let derive_key2 = derive::key(
      &derive_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key2.policy.time, 0);
    assert_eq!(derive_key2.policy.memory, 32768);
    assert_eq!(derive_key2.key, derive_key.key);

    Ok(())
  }

  #[test]
  fn strengthen_time_and_memory() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![crate::setup::factors::password("password1", PasswordOptions {
      id: Some("password1".to_string()),
    })?];

    let setup_key = setup::key(&setup_factors, MFKDF2Options::default())?;

    assert_eq!(setup_key.policy.time, 0);
    assert_eq!(setup_key.policy.memory, 0);

    let mut derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key.policy.time, 0);
    assert_eq!(derive_key.policy.memory, 0);

    derive_key.strengthen(3, 16384)?;

    assert_eq!(derive_key.policy.time, 3);
    assert_eq!(derive_key.policy.memory, 16384);

    let derive_key2 = derive::key(
      &derive_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key2.policy.time, 3);
    assert_eq!(derive_key2.policy.memory, 16384);
    assert_eq!(derive_key2.key, derive_key.key);

    Ok(())
  }

  #[test]
  fn strengthen_multiple() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![crate::setup::factors::password("password1", PasswordOptions {
      id: Some("password1".to_string()),
    })?];
    let setup_key = setup::key(&setup_factors, MFKDF2Options::default())?;

    let mut derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key.key, setup_key.key);

    derive_key.strengthen(2, 8192)?;
    assert_eq!(derive_key.policy.time, 2);
    assert_eq!(derive_key.policy.memory, 8192);

    let mut derive_key2 = derive::key(
      &derive_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key2.key, derive_key.key);

    let mut derive_policy = derive_key.policy.clone();
    derive_policy.time = 0;
    derive_policy.memory = 0;

    let derive_key3 = derive::key(
      &derive_policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    );
    assert!(matches!(derive_key3, Err(error::MFKDF2Error::PolicyIntegrityCheckFailed)));

    derive_key2.strengthen(3, 16384)?;
    assert_eq!(derive_key2.policy.time, 3);
    assert_eq!(derive_key2.policy.memory, 16384);

    let derive_key3 = derive::key(
      &derive_key2.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key3.policy.time, 3);
    assert_eq!(derive_key3.policy.memory, 16384);
    assert_eq!(derive_key3.key, derive_key2.key);

    let mut derive_key2_policy = derive_key2.policy.clone();
    derive_key2_policy.time = 0;
    derive_key2_policy.memory = 0;

    let derive_key4 = derive::key(
      &derive_key2_policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    );
    assert!(matches!(derive_key4, Err(error::MFKDF2Error::PolicyIntegrityCheckFailed)));

    Ok(())
  }

  #[test]
  fn strengthening_with_other_factors() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
    ];

    let setup_key = setup::key(&setup_factors, MFKDF2Options::default())?;

    let mut derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password2".to_string(), derive_factors::password("password2")?),
      ]),
      true,
      false,
    )?;

    assert_eq!(derive_key.key, setup_key.key);

    derive_key.strengthen(2, 8192)?;
    assert_eq!(derive_key.policy.time, 2);
    assert_eq!(derive_key.policy.memory, 8192);

    let derive_key2 = derive::key(
      &derive_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password2".to_string(), derive_factors::password("password2")?),
      ]),
      true,
      false,
    )?;

    assert_eq!(derive_key2.key, setup_key.key);

    let mut derive_key2 = derive_key2;
    derive_key2.strengthen(0, 0)?;
    assert_eq!(derive_key2.policy.time, 0);
    assert_eq!(derive_key2.policy.memory, 0);

    let derive_key3 = derive::key(
      &derive_key2.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password2".to_string(), derive_factors::password("password2")?),
      ]),
      true,
      false,
    )?;

    assert_eq!(derive_key3.policy.time, 0);
    assert_eq!(derive_key3.policy.memory, 0);
    assert_eq!(derive_key3.key, setup_key.key);

    Ok(())
  }

  #[test]
  fn strengthening_with_reconstitution() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
    ];

    let setup_key = setup::key(&setup_factors, MFKDF2Options::default())?;

    let mut derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password2".to_string(), derive_factors::password("password2")?),
      ]),
      true,
      false,
    )?;

    assert_eq!(derive_key.key, setup_key.key);

    derive_key.strengthen(2, 8192)?;
    assert_eq!(derive_key.policy.time, 2);
    assert_eq!(derive_key.policy.memory, 8192);

    derive_key.set_threshold(1)?;
    derive_key.remove_factor("password2")?;

    let derive_key2 = derive::key(
      &derive_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key2.key, setup_key.key);

    Ok(())
  }
}
