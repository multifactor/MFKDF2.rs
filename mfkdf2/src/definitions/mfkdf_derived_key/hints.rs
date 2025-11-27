//! Probabilistic factor hints.
//!
//! This module implements the MFKDF2 "hints" feature. Hints allow you to
//! store a small number of bits of entropy derived from one or more input
//! factors directly in the public MFKDF2 policy.
//!
//! Storing a `b`-bit hint for a factor reduces the brute-force strength of the
//! final derived key by approximately `b` bits, but allows clients to
//! probabilistically validate whether a candidate factor is likely to be
//! correct before attempting a full derivation.
use std::fmt::Write;

use base64::{Engine, engine::general_purpose};

use crate::{
  crypto::{hkdf_sha256_with_info, hmacsha256},
  definitions::MFKDF2DerivedKey,
  error::MFKDF2Error,
};

impl MFKDF2DerivedKey {
  /// Compute a probabilistic hint for a single factor.
  ///
  /// This function derives a deterministic bitstring from the secret material
  /// backing the given factor and returns the least-significant `bits` of that
  /// string as a binary `String` (e.g. `"0101010"`). These bits can be stored
  /// in the public policy and later recomputed for candidate factors to
  /// probabilistically validate whether they are correct.
  ///
  /// Storing a `b`-bit hint for a factor reduces the brute-force strength of
  /// the final derived key by approximately `b` bits.
  ///
  /// # Errors
  ///
  /// - Returns [`MFKDF2Error::InvalidHintLength`] if `bits == 0`.
  /// - Returns [`MFKDF2Error::MissingFactor`] if no factor with `factor_id` exists in the policy.
  /// - Propagates any cryptographic or decoding errors encountered while deriving the factor
  ///   material.
  pub fn get_hint(&self, factor_id: &str, bits: u8) -> Result<String, MFKDF2Error> {
    if bits == 0 {
      return Err(MFKDF2Error::InvalidHintLength("bits must be greater than 0"));
    }

    // derive internal key
    let internal_key = self.derive_internal_key()?;

    let factor_data = self
      .policy
      .factors
      .iter()
      .find(|f| f.id == factor_id)
      .ok_or_else(|| MFKDF2Error::MissingFactor(factor_id.to_string()))?;
    let pad = base64::Engine::decode(&general_purpose::STANDARD, factor_data.secret.as_bytes())?;
    let salt = base64::Engine::decode(&general_purpose::STANDARD, factor_data.salt.as_bytes())?;
    let secret_key = crate::crypto::hkdf_sha256_with_info(
      &internal_key,
      &salt,
      format!("mfkdf2:factor:secret:{factor_id}").as_bytes(),
    );

    let factor_material = crate::crypto::decrypt(pad, &secret_key);
    let buffer = crate::crypto::hkdf_sha256_with_info(
      &factor_material,
      &salt,
      format!("mfkdf2:factor:hint:{factor_id}").as_bytes(),
    );

    let binary_string = buffer.iter().fold(String::new(), |mut acc, byte| {
      write!(&mut acc, "{byte:08b}").unwrap();
      acc
    });

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

  /// Compute and store a probabilistic hint for a factor in the public policy.
  ///
  /// This is a convenience wrapper around [`MFKDF2DerivedKey::get_hint`] that
  /// computes a hint and stores it on the matching factor within the
  /// [Policy](`crate::policy::Policy`) associated with this
  /// derived key.
  ///
  /// If `bits` is `None`, a default of `7` bits is used, which gives legitimate
  /// users a greater than 99% chance of detecting an incorrect factor while
  /// leaking only a negligible amount of information about the underlying
  /// factor to most adversaries.
  ///
  /// # Examples
  ///
  /// Store a 7-bit hint for a password factor during setup and reuse it during
  /// derivation:
  ///
  /// ```rust
  /// use std::collections::HashMap;
  ///
  /// use mfkdf2::{
  ///   definitions::MFKDF2Options,
  ///   derive,
  ///   error::MFKDF2Error,
  ///   setup::{
  ///     self,
  ///     factors::{password, password::PasswordOptions},
  ///   },
  /// };
  /// // Create a policy with a single password factor.
  /// let mut setup_key = setup::key(
  ///   &[password("correct horse battery staple", PasswordOptions {
  ///     id: Some("password1".to_string()),
  ///   })?],
  ///   MFKDF2Options::default(),
  /// )?;
  ///
  /// // Store a 7-bit hint for the password factor in the public policy.
  /// setup_key.add_hint("password1", None)?;
  ///
  /// // Later, compute the expected hint for a candidate password.
  /// let candidate_hint = setup_key.get_hint("password1", 7)?;
  /// assert_eq!(candidate_hint.len(), 7);
  ///
  /// // During derivation, the library will automatically compare any stored
  /// // hints and return `MFKDF2Error::HintMismatch` if they do not match.
  /// let derived_key = derive::key(
  ///   &setup_key.policy,
  ///   HashMap::from([(
  ///     "password1".to_string(),
  ///     derive::factors::password("correct horse battery staple")?,
  ///   )]),
  ///   true,  // integrity
  ///   false, // allow_partial
  /// )?;
  ///
  /// assert_eq!(derived_key.key, setup_key.key);
  /// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
  /// ```
  pub fn add_hint(&mut self, factor_id: &str, bits: Option<u8>) -> Result<(), MFKDF2Error> {
    // verify policy integrity
    if !self.policy.hmac.is_empty() {
      let integrity_data = self.policy.extract();
      let salt = general_purpose::STANDARD.decode(&self.policy.salt)?;
      let integrity_key = hkdf_sha256_with_info(&self.key, &salt, "mfkdf2:integrity".as_bytes());
      let digest = hmacsha256(&integrity_key, &integrity_data);
      let hmac = general_purpose::STANDARD.encode(digest);
      if self.policy.hmac != hmac {
        return Err(MFKDF2Error::PolicyIntegrityCheckFailed);
      }
    }

    let bits = bits.unwrap_or(7);
    let hint = self.get_hint(factor_id, bits);
    let factor_data = self.policy.factors.iter_mut().find(|f| f.id == factor_id).unwrap();
    factor_data.hint = Some(hint?);

    // update the hmac of the policy
    if !self.policy.hmac.is_empty() {
      // compute the new hmac of the policy
      let integrity_data = self.policy.extract();
      let salt = general_purpose::STANDARD.decode(&self.policy.salt)?;
      let integrity_key = hkdf_sha256_with_info(&self.key, &salt, "mfkdf2:integrity".as_bytes());
      let digest = hmacsha256(&integrity_key, &integrity_data);
      let hmac = general_purpose::STANDARD.encode(digest);
      self.policy.hmac = hmac;
    }

    Ok(())
  }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_get_hint(
  derived_key: &MFKDF2DerivedKey,
  factor_id: &str,
  bits: u8,
) -> Result<String, MFKDF2Error> {
  derived_key.get_hint(factor_id, bits)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_add_hint(
  derived_key: MFKDF2DerivedKey,
  factor_id: &str,
  bits: Option<u8>,
) -> Result<MFKDF2DerivedKey, MFKDF2Error> {
  let mut derived_key = derived_key;
  derived_key.add_hint(factor_id, bits)?;
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
  fn get_hint() -> Result<(), error::MFKDF2Error> {
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      MFKDF2Options::default(),
    )?;

    let hint = setup_key.get_hint("password1", 7)?;
    assert!(hint.len() == 7);
    assert!(hint.chars().all(|c| c == '0' || c == '1'));

    let hinta = setup_key.get_hint("password1", 24)?;
    assert!(hinta.len() == 24);
    assert!(hinta.chars().all(|c| c == '0' || c == '1'));

    let derive_key = derive::key(
      &setup_key.policy,
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
      &setup_key.policy,
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
    let mut setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      MFKDF2Options { integrity: Some(false), ..Default::default() },
    )?;

    setup_key.add_hint("password1", None)?; // Default to 7 bits 
    assert!(setup_key.policy.factors[0].hint.is_some());
    assert_eq!(setup_key.policy.factors[0].hint.as_ref().unwrap().len(), 7);

    setup_key.add_hint("password1", Some(24))?;
    assert!(setup_key.policy.factors[0].hint.is_some());
    assert_eq!(setup_key.policy.factors[0].hint.as_ref().unwrap().len(), 24);

    let derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      false,
      false,
    );
    assert!(derive_key.is_ok());
    assert_eq!(derive_key.unwrap().key, setup_key.key);

    let wrong_password = derive_factors::password("password2")?;
    let derive_result = derive::key(
      &setup_key.policy,
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
    let setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      MFKDF2Options { integrity: Some(true), ..Default::default() },
    )?;

    let result = setup_key.get_hint("password1", 0);
    assert!(matches!(result, Err(error::MFKDF2Error::InvalidHintLength(_))));

    Ok(())
  }

  // Below tests demonstrate the entropy leakage of the hint feature. With integrity turned off, an
  // adversary can modify the hint and derive the key successfully. If hint mismatches, then
  // derivation fails with `HintMismatch` error. This leaks 1 bit of information for each
  // derivation. The adversary can repeatedly guess the hint, launching a brute-force attack on the
  // factor.
  // If integrity is turned on, then the adversary cannot modify the hint and derive the key
  // successfully. If hint mismatches, then derivation fails with `PolicyIntegrityCheckFailed`
  // error. This does not leak any information about the factor.
  #[test]
  fn hint_entropy_leakage_no_integrity() -> Result<(), error::MFKDF2Error> {
    let mut setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      MFKDF2Options { integrity: Some(false), ..Default::default() },
    )?;

    // 7 bit hint added to the policy
    setup_key.add_hint("password1", None)?;

    // derive the key with the correct password
    let derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      false,
      false,
    )?;

    assert_eq!(derive_key.key, setup_key.key);

    // modify hint
    let mut hint = setup_key.get_hint("password1", 7)?;
    hint.insert(0, '0');

    let mut modified_setup_key_policy = setup_key.policy.clone();
    modified_setup_key_policy.factors[0].hint = Some(hint);

    // derive the key with the modified hint
    let mut modified_derive_key = derive::key(
      &modified_setup_key_policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      false,
      false,
    );

    if matches!(modified_derive_key, Err(error::MFKDF2Error::HintMismatch(_))) {
      let mut hint = setup_key.get_hint("password1", 7)?;
      hint.insert(0, '1');
      modified_setup_key_policy.factors[0].hint = Some(hint);
      modified_derive_key = derive::key(
        &modified_setup_key_policy,
        HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
        false,
        false,
      );
    }

    assert_eq!(modified_derive_key.unwrap().key, derive_key.key);

    Ok(())
  }

  #[test]
  fn hint_entropy_leakage_with_integrity() -> Result<(), error::MFKDF2Error> {
    let mut setup_key = setup::key(
      &[crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?],
      MFKDF2Options { integrity: Some(true), ..Default::default() },
    )?;

    // 7 bit hint added to the policy
    setup_key.add_hint("password1", None)?;

    // derive the key with the correct password
    let derive_key = derive::key(
      &setup_key.policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    )?;

    assert_eq!(derive_key.key, setup_key.key);

    // modify hint
    let mut hint = setup_key.get_hint("password1", 7)?;
    hint.insert(0, '0');

    let mut modified_setup_key_policy = setup_key.policy.clone();
    modified_setup_key_policy.factors[0].hint = Some(hint);

    // derive the key with the modified hint
    let modified_derive_key1 = derive::key(
      &modified_setup_key_policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    );

    let mut modified_hint = setup_key.get_hint("password1", 7)?;
    modified_hint.insert(0, '1');
    modified_setup_key_policy.factors[0].hint = Some(modified_hint);

    let modified_derive_key2 = derive::key(
      &modified_setup_key_policy,
      HashMap::from([("password1".to_string(), derive_factors::password("password1")?)]),
      true,
      false,
    );

    assert!(
      matches!(modified_derive_key1, Err(error::MFKDF2Error::PolicyIntegrityCheckFailed))
        || matches!(modified_derive_key2, Err(error::MFKDF2Error::PolicyIntegrityCheckFailed))
    );

    Ok(())
  }
}
