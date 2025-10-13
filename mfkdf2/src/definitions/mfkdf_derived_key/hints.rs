use base64::engine::general_purpose;

use crate::{definitions::MFKDF2DerivedKey, error::MFKDF2Error};

impl MFKDF2DerivedKey {
  pub fn get_hint(&self, factor_id: &str, bits: u8) -> Result<String, MFKDF2Error> {
    if bits == 0 {
      return Err(MFKDF2Error::InvalidHintLength("bits must be greater than 0"));
    }

    let factor_data = self.policy.factors.iter().find(|f| f.id == factor_id).unwrap();
    let pad =
      base64::Engine::decode(&general_purpose::STANDARD, factor_data.secret.as_bytes()).unwrap();
    let salt =
      base64::Engine::decode(&general_purpose::STANDARD, factor_data.salt.as_bytes()).unwrap();
    let secret_key = crate::crypto::hkdf_sha256_with_info(
      &self.key,
      &salt,
      format!("mfkdf2:factor:secret:{}", factor_id).as_bytes(),
    );

    let factor_material = crate::crypto::decrypt(pad, &secret_key);
    let buffer = crate::crypto::hkdf_sha256_with_info(
      &factor_material,
      &salt,
      format!("mfkdf2:factor:hint:{}", factor_id).as_bytes(),
    );

    let binary_string: String =
      buffer.iter().map(|byte| format!("{:08b}", byte)).collect::<Vec<_>>().join("");
    Ok(
      binary_string
        .chars()
        .rev()
        .take(bits as usize)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>(),
    )
  }

  pub fn add_hint(&mut self, factor_id: &str, bits: u8) -> Result<(), MFKDF2Error> {
    let hint = self.get_hint(factor_id, bits);
    let factor_data = self.policy.factors.iter_mut().find(|f| f.id == factor_id).unwrap();
    factor_data.hint = Some(hint?);
    Ok(())
  }
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_get_hint(
  derived_key: MFKDF2DerivedKey,
  factor_id: &str,
  bits: u8,
) -> Result<String, MFKDF2Error> {
  derived_key.get_hint(factor_id, bits)
}

// TODO (@lonerapier): this should take a mut reference to the derived key
#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_add_hint(
  derived_key: MFKDF2DerivedKey,
  factor_id: &str,
  bits: u8,
) -> Result<MFKDF2DerivedKey, MFKDF2Error> {
  let mut derived_key = derived_key;
  derived_key.add_hint(factor_id, bits)?;
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
  fn get_hint() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![crate::setup::factors::password("password1", PasswordOptions {
      id: Some("password1".to_string()),
    })?];

    let setup_key = setup::key(setup_factors, MFKDF2Options::default())?;

    let hint = setup_key.get_hint("password1", 7)?;
    assert!(hint.len() == 7);
    assert!(hint.chars().all(|c| c == '0' || c == '1'));

    let hinta = setup_key.get_hint("password1", 24)?;
    assert!(hinta.len() == 24);
    assert!(hinta.chars().all(|c| c == '0' || c == '1'));

    let derive_key = derive::key(
      setup_key.policy.clone(),
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key.key, setup_key.key);

    let hint2 = derive_key.get_hint("password1", 7)?;
    assert_eq!(hint2, hint);

    let hinta2 = derive_key.get_hint("password1", 24)?;
    assert_eq!(hinta2, hinta);

    let derive_key2 = derive::key(
      setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("wrongpassword")?)]),
      false,
      false,
    )?;

    let hinta3 = derive_key2.get_hint("password1", 24)?;
    assert_ne!(hinta3, hinta);

    Ok(())
  }

  #[test]
  fn add_hint() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![crate::setup::factors::password("password1", PasswordOptions {
      id: Some("password1".to_string()),
    })?];

    let mut setup_key =
      setup::key(setup_factors, MFKDF2Options { integrity: Some(false), ..Default::default() })?;

    setup_key.add_hint("password1", 7)?; // Default to 7 bits as per original JS test
    assert!(setup_key.policy.factors[0].hint.is_some());
    assert_eq!(setup_key.policy.factors[0].hint.as_ref().unwrap().len(), 7);

    setup_key.add_hint("password1", 24)?;
    assert!(setup_key.policy.factors[0].hint.is_some());
    assert_eq!(setup_key.policy.factors[0].hint.as_ref().unwrap().len(), 24);

    let derive_key = derive::key(
      setup_key.policy.clone(),
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      false,
      false,
    );
    assert!(matches!(derive_key, Ok(_)));
    assert_eq!(derive_key.unwrap().key, setup_key.key);

    let wrong_password = derive_factors::password("password2")?;
    let derive_result = derive::key(
      setup_key.policy,
      HashMap::from([("password1".to_string(), wrong_password)]),
      false,
      false,
    );

    assert!(
      matches!(derive_result, Err(error::MFKDF2Error::HintMismatch(factor_id)) if factor_id == "password1")
    );

    Ok(())
  }

  #[test]
  fn coverage() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![crate::setup::factors::password("password1", PasswordOptions {
      id: Some("password1".to_string()),
    })?];

    let setup_key =
      setup::key(setup_factors, MFKDF2Options { integrity: Some(false), ..Default::default() })?;

    let result = setup_key.get_hint("password1", 0);
    assert!(matches!(result, Err(error::MFKDF2Error::InvalidHintLength(_))));

    Ok(())
  }
}
