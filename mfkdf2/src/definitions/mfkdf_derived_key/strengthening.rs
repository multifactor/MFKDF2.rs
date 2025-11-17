use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose};

use crate::{crypto::encrypt, definitions::MFKDF2DerivedKey, error::MFKDF2Result};

impl MFKDF2DerivedKey {
  pub fn strengthen(&mut self, time: u32, memory: u32) -> MFKDF2Result<()> {
    self.policy.time = time;
    self.policy.memory = memory;

    let mut kek = [0u8; 32];

    let salt = general_purpose::STANDARD.decode(&self.policy.salt).unwrap();

    // TODO (@lonerapier): what if the policy has a stack key?
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

    let policy_key = encrypt(self.key.as_ref(), &kek);
    self.policy.key = general_purpose::STANDARD.encode(policy_key);
    Ok(())
  }
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_strengthen(
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
    derive,
    derive::factors as derive_factors,
    error,
    setup::{self, factors::password::PasswordOptions, key::MFKDF2Options},
  };

  #[test]
  fn strengthen_time() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![crate::setup::factors::password("password1", PasswordOptions {
      id: Some("password1".to_string()),
    })?];

    let setup_key = setup::key(setup_factors, MFKDF2Options::default())?;

    assert_eq!(setup_key.policy.time, 0);

    let mut derive_key = derive::key(
      setup_key.policy,
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
      derive_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      false,
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

    let setup_key = setup::key(setup_factors, MFKDF2Options::default())?;

    assert_eq!(setup_key.policy.memory, 0);

    let mut derive_key = derive::key(
      setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key.policy.memory, 0);

    derive_key.strengthen(0, 32768)?;

    assert_eq!(derive_key.policy.time, 0);
    assert_eq!(derive_key.policy.memory, 32768);

    let derive_key2 = derive::key(
      derive_key.policy,
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

    let setup_key = setup::key(setup_factors, MFKDF2Options::default())?;

    assert_eq!(setup_key.policy.time, 0);
    assert_eq!(setup_key.policy.memory, 0);

    let mut derive_key = derive::key(
      setup_key.policy,
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
      derive_key.policy,
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
    let setup_key = setup::key(setup_factors, MFKDF2Options::default())?;

    let mut derive_key = derive::key(
      setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key.key, setup_key.key);

    derive_key.strengthen(2, 8192)?;
    assert_eq!(derive_key.policy.time, 2);
    assert_eq!(derive_key.policy.memory, 8192);

    let mut derive_key2 = derive::key(
      derive_key.policy.clone(),
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key2.key, derive_key.key);

    let mut derive_policy = derive_key.policy.clone();
    derive_policy.time = 0;
    derive_policy.memory = 0;

    let derive_key3 = derive::key(
      derive_policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    );
    assert!(matches!(derive_key3, Err(error::MFKDF2Error::PolicyIntegrityCheckFailed)));

    derive_key2.strengthen(3, 16384)?;
    assert_eq!(derive_key2.policy.time, 3);
    assert_eq!(derive_key2.policy.memory, 16384);

    let derive_key3 = derive::key(
      derive_key2.policy.clone(),
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
      derive_key2_policy,
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

    let setup_key = setup::key(setup_factors, MFKDF2Options::default())?;

    let mut derive_key = derive::key(
      setup_key.policy,
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
      derive_key.policy,
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
      derive_key2.policy,
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

    let setup_key = setup::key(setup_factors, MFKDF2Options::default())?;

    let mut derive_key = derive::key(
      setup_key.policy,
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
      derive_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key2.key, setup_key.key);

    Ok(())
  }
}
