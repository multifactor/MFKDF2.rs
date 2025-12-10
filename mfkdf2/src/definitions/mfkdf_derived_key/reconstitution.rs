//! # MFKDF2 Factor Recovery
//!
//! Reconstitution refers to the process of modifying the factors used to derive a key without
//! changing the value of the derived key.
//!
//! Consider a key derived from a password, a TOTP factor, and a UUID factor. Using threshold
//! recovery, the user can derive the key with only a subset of factors inside the policy.
//!
//! **Note**: MFKDF2 provides no mechanism to invalidate old policies. When threshold is increased
//! via reconstitution, old policies can still be used to derive keys.
//!
//! ```rust
//! # use std::collections::HashMap;
//! # use uuid::Uuid;
//! # use mfkdf2::{
//! #   setup,
//! #   setup::{
//! #     factors::{password::PasswordOptions, totp::TOTPOptions, uuid::UUIDOptions},
//! #   },
//! #   definitions::MFKDF2Options,
//! # };
//! #
//! let uuid = Uuid::parse_str("f9bf78b9-54e7-4696-97dc-5e750de4c592").unwrap();
//! let setup_factors = vec![
//!   setup::factors::password("password1", PasswordOptions { id: Some("password1".to_string()) })?,
//!   setup::factors::totp(TOTPOptions {
//!     id: Some("totp1".to_string()),
//!     ..Default::default()
//!   })?,
//!   setup::factors::uuid(UUIDOptions {
//!     id:   Some("uuid1".to_string()),
//!     uuid: Some(uuid),
//!   })?,
//! ];
//! let mut setup_key = setup::key(&setup_factors, MFKDF2Options::default())?;
//!
//! // Let's say now the user wishes to reset the password. The `MFKDF2DerivedKey` can be updated to reflect the new password like so:
//! setup_key.recover_factor(setup::factors::password("newPassword1", PasswordOptions {
//!   id: Some("password1".to_string()),
//! })?);
//!
//! Ok::<(), mfkdf2::error::MFKDF2Error>(())
//! ```
//!
//! The key can now be derived with the modified credentials:
//! ```rust
//! # use std::collections::HashMap;
//! # use uuid::Uuid;
//! # use std::time::{SystemTime, UNIX_EPOCH};
//! # use mfkdf2::{
//! #   derive,
//! #   derive::factors::{
//! #     password as derive_password, totp as derive_totp, uuid as derive_uuid,
//! #   },
//! #   setup,
//! #   setup::{
//! #     factors::{password::PasswordOptions, totp::TOTPOptions, uuid::UUIDOptions},
//! #   },
//! #   definitions::MFKDF2Options,
//! #   otpauth::HashAlgorithm,
//! # };
//! #
//! # let uuid = Uuid::parse_str("f9bf78b9-54e7-4696-97dc-5e750de4c592").unwrap();
//! # let setup_factors = vec![
//! #   setup::factors::password("password1", PasswordOptions { id: Some("password1".to_string()) })?,
//! #   setup::factors::totp(TOTPOptions { id: Some("totp1".to_string()), ..Default::default() })?,
//! #   setup::factors::uuid(UUIDOptions { id: Some("uuid1".to_string()), uuid: Some(uuid) })?,
//! # ];
//! # let secret = if let mfkdf2::definitions::FactorType::TOTP(ref f) = setup_factors[1].factor_type {
//! #   f.config.secret.clone()
//! # } else {
//! #   unreachable!()
//! # };
//! # let mut setup_key = setup::key(&setup_factors, MFKDF2Options::default())?;
//!
//! # setup_key.recover_factor(setup::factors::password("newPassword1", PasswordOptions {
//! #   id: Some("password1".to_string()),
//! # })?);
//!
//! # let step = 30;
//! # let digits = 6;
//! # let hash = HashAlgorithm::Sha1;
//! # let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
//! # let counter = now_ms / (step * 1000);
//! # let code = mfkdf2::otpauth::generate_otp_token(&secret[..20], counter, &hash, digits);
//!
//! let mut derived_key = derive::key(
//!   &setup_key.policy,
//!   HashMap::from([
//!     ("password1".to_string(), derive::factors::password("newPassword1")?),
//!     ("totp1".to_string(), derive::factors::totp(code, None)?),
//!     ("uuid1".to_string(), derive::factors::uuid(uuid)?),
//!   ]),
//!   true,
//!   false,
//! )?;
//!
//! assert_eq!(derived_key.key, setup_key.key);
//! Ok::<(), mfkdf2::error::MFKDF2Error>(())
//! ```

use std::collections::{BTreeMap, HashSet};

use base64::{Engine, engine::general_purpose};

use crate::{
  constants::SECRET_SHARING_POLY,
  crypto::{encrypt, hkdf_sha256_with_info, hmacsha256},
  definitions::{MFKDF2DerivedKey, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  policy::PolicyFactor,
};

impl MFKDF2DerivedKey {
  /// Sets a new threshold for the key.
  pub fn set_threshold(&mut self, threshold: u8) -> MFKDF2Result<()> {
    self.reconstitute(&[], &[], Some(threshold))
  }

  /// Removes a factor from the key.
  pub fn remove_factor(&mut self, factor: &str) -> MFKDF2Result<()> {
    self.reconstitute(&[factor], &[], None)
  }

  /// Removes multiple factors from the key.
  pub fn remove_factors(&mut self, factors: &[&str]) -> MFKDF2Result<()> {
    self.reconstitute(factors, &[], None)
  }

  /// Adds a factor to the key.
  pub fn add_factor(&mut self, factor: MFKDF2Factor) -> MFKDF2Result<()> {
    self.reconstitute(&[], &[factor], None)
  }

  /// Adds multiple factors to the key.
  pub fn add_factors(&mut self, factors: &[MFKDF2Factor]) -> MFKDF2Result<()> {
    self.reconstitute(&[], factors, None)
  }

  /// Recovers a factor from the key.
  pub fn recover_factor(&mut self, factor: MFKDF2Factor) -> MFKDF2Result<()> {
    self.reconstitute(&[], &[factor], None)
  }

  /// Recovers multiple factors from the key.
  pub fn recover_factors(&mut self, factors: &[MFKDF2Factor]) -> MFKDF2Result<()> {
    self.reconstitute(&[], factors, None)
  }

  /// Reconstitutes the key with the given factors.
  pub fn reconstitute(
    &mut self,
    remove_factor: &[&str],
    add_factor: &[MFKDF2Factor],
    threshold: Option<u8>,
  ) -> MFKDF2Result<()> {
    let mut factors = BTreeMap::new();
    let mut material: BTreeMap<&str, [u8; 32]> = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    let mut data = BTreeMap::new();

    let threshold = threshold.unwrap_or(self.policy.threshold);

    // derive internal key for deriving separate keys for parameters, secret, and integrity
    let mut internal_key = self.derive_internal_key()?;

    for factor in &self.policy.factors {
      factors.insert(factor.id.clone(), factor.clone());

      let pad = general_purpose::STANDARD.decode(&factor.secret)?;
      let salt = general_purpose::STANDARD.decode(&factor.salt)?;
      let secret_key = hkdf_sha256_with_info(
        &internal_key,
        &salt,
        format!("mfkdf2:factor:secret:{}", factor.id).as_bytes(),
      );
      let factor_material = crate::crypto::decrypt(pad, &secret_key);

      material.insert(
        factor.id.as_str(),
        factor_material.try_into().map_err(|_| MFKDF2Error::TryFromVec)?,
      );
    }

    for &factor in remove_factor {
      if !factors.contains_key(factor) {
        return Err(MFKDF2Error::MissingFactor(factor.to_string()));
      }

      factors.remove(factor);
      material.remove(factor);
    }

    for factor in add_factor {
      let mut salt = [0u8; 32];
      crate::rng::fill_bytes(&mut salt);

      let id = factor.id.clone().ok_or(MFKDF2Error::MissingFactorId)?;

      let params_key = hkdf_sha256_with_info(
        &internal_key,
        &salt,
        format!("mfkdf2:factor:params:{id}").as_bytes(),
      );
      let params = factor.factor_type.setup().params(params_key.into())?;

      let new_factor = PolicyFactor {
        id: id.clone(),
        kind: factor.kind(),
        salt: general_purpose::STANDARD.encode(salt),
        params,
        hint: None,
        pad: String::new(),
        secret: String::new(),
      };

      factors.insert(id.clone(), new_factor);
      outputs.insert(id.clone(), factor.factor_type.setup().output());
      data.insert(id.clone(), factor.data());
      if material.contains_key(id.as_str()) {
        material.remove(id.as_str());
      }
    }

    // add factors id uniqueness
    let ids = add_factor
      .iter()
      .map(|f| f.id.clone().ok_or(MFKDF2Error::MissingFactorId))
      .collect::<Result<Vec<String>, MFKDF2Error>>()?;
    let set = ids.iter().cloned().collect::<HashSet<String>>();
    if set.len() != ids.len() {
      return Err(MFKDF2Error::DuplicateFactorId);
    }

    if threshold > factors.len() as u8 {
      return Err(MFKDF2Error::InvalidThreshold);
    }

    let dealer =
      ssskit::SecretSharing(threshold).dealer_rng(&self.secret, &mut crate::rng::GlobalRng);
    let shares: Vec<Vec<u8>> = dealer
      .take(factors.len())
      .map(|s: ssskit::Share<SECRET_SHARING_POLY>| Vec::from(&s))
      .collect();

    let mut new_factors = vec![];

    for (id, (_, mut factor)) in factors.into_iter().enumerate() {
      let salt = general_purpose::STANDARD.decode(&factor.salt)?;

      let stretched = if material.contains_key(factor.id.as_str()) {
        material.get(factor.id.as_str()).unwrap()
      } else if data.contains_key(factor.id.as_str()) {
        &hkdf_sha256_with_info(
          data.get(factor.id.as_str()).unwrap(),
          &salt,
          format!("mfkdf2:factor:pad:{}", factor.id).as_bytes(),
        )
      } else {
        return Err(MFKDF2Error::TryFromVec);
      };

      let mut secret_key = hkdf_sha256_with_info(
        &internal_key,
        &salt,
        format!("mfkdf2:factor:secret:{}", factor.id).as_bytes(),
      );

      factor.pad = general_purpose::STANDARD.encode(encrypt(&shares[id], stretched));
      factor.secret = general_purpose::STANDARD.encode(encrypt(stretched, &secret_key));

      new_factors.push(factor);

      #[cfg(feature = "zeroize")]
      {
        use zeroize::Zeroize;
        secret_key.zeroize();
      }
    }

    self.policy.factors = new_factors;
    self.policy.threshold = threshold;
    self.outputs = outputs.into_iter().collect();
    self.shares = shares;

    if !self.policy.hmac.is_empty() {
      let salt = general_purpose::STANDARD.decode(&self.policy.salt)?;
      let integrity_key =
        hkdf_sha256_with_info(&internal_key, &salt, "mfkdf2:integrity".as_bytes());
      let integrity_data = self.policy.extract();
      let digest = hmacsha256(&integrity_key, &integrity_data);
      self.policy.hmac = general_purpose::STANDARD.encode(digest);

      #[cfg(feature = "zeroize")]
      {
        use zeroize::Zeroize;
        internal_key.zeroize();
      }
    }

    Ok(())
  }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_set_threshold(
  derived_key: MFKDF2DerivedKey,
  threshold: u8,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.set_threshold(threshold)?;
  Ok(derived_key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_remove_factor(
  derived_key: MFKDF2DerivedKey,
  factor: &str,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.remove_factor(factor)?;
  Ok(derived_key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_remove_factors(
  derived_key: MFKDF2DerivedKey,
  factors: &[String],
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.remove_factors(factors.iter().map(String::as_str).collect::<Vec<&str>>().as_ref())?;
  Ok(derived_key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_add_factor(
  derived_key: MFKDF2DerivedKey,
  factor: MFKDF2Factor,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.add_factor(factor)?;
  Ok(derived_key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_add_factors(
  derived_key: MFKDF2DerivedKey,
  factors: &[MFKDF2Factor],
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.add_factors(factors)?;
  Ok(derived_key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_recover_factor(
  derived_key: MFKDF2DerivedKey,
  factor: MFKDF2Factor,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.recover_factor(factor)?;
  Ok(derived_key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_recover_factors(
  derived_key: MFKDF2DerivedKey,
  factors: &[MFKDF2Factor],
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.recover_factors(factors)?;
  Ok(derived_key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_reconstitute(
  derived_key: MFKDF2DerivedKey,
  remove_factor: &[String],
  add_factor: &[MFKDF2Factor],
  threshold: Option<u8>,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.reconstitute(
    remove_factor.iter().map(String::as_str).collect::<Vec<&str>>().as_ref(),
    add_factor,
    threshold,
  )?;
  Ok(derived_key)
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use crate::{
    definitions::MFKDF2Options,
    derive::{self, factors as derive_factors},
    error,
    setup::{self, factors::password::PasswordOptions},
  };

  #[test]
  fn set_threshold() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
      crate::setup::factors::password("password4", PasswordOptions {
        id: Some("password4".to_string()),
      })?,
    ];

    let mut setup = setup::key(&setup_factors, MFKDF2Options {
      threshold: Some(3),
      integrity: Some(false),
      ..Default::default()
    })?;
    let setup_key = setup.key.clone();

    let derive_factors = HashMap::from([
      ("password1".to_string(), derive_factors::password("password1")?),
      ("password2".to_string(), derive_factors::password("password2")?),
    ]);

    let result = derive::key(&setup.policy, derive_factors.clone(), false, false);
    assert!(result.is_err(), "Derivation should fail with threshold 3 and only 2 factors provided");

    setup.set_threshold(2)?;

    let derive = derive::key(&setup.policy, derive_factors, false, false)?;

    assert_eq!(derive.key, setup_key);

    Ok(())
  }

  #[test]
  fn remove_factor_test() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;
    let key = setup_key.key.clone();

    let derive1 = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password2".to_string(), derive_factors::password("password2")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive1.key, key);

    setup_key.remove_factor("password1")?;

    let mut derive2 = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password2".to_string(), derive_factors::password("password2")?),
        ("password3".to_string(), derive_factors::password("password3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive2.key, key);

    let result = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password2".to_string(), derive_factors::password("password2")?),
      ]),
      false,
      false,
    );
    assert!(result.is_err(), "Derivation should fail after removing password1");

    let result = derive::key(
      &derive2.policy,
      HashMap::from([("password2".to_string(), derive_factors::password("password2")?)]),
      false,
      false,
    );
    assert!(result.is_err(), "Derivation should fail after removing password2 and threshold is 2");

    derive2.set_threshold(1)?;

    derive2.remove_factor("password2")?;

    let mut derive_factors3 = HashMap::new();
    derive_factors3.insert("password3".to_string(), derive_factors::password("password3")?);

    let derive3 = derive::key(&derive2.policy, derive_factors3, false, false)?;
    assert_eq!(derive3.key, key);

    let result = derive::key(
      &derive2.policy,
      HashMap::from([("password2".to_string(), derive_factors::password("password2")?)]),
      false,
      false,
    );
    assert!(result.is_err(), "Derivation should fail for removed password2 factor");

    Ok(())
  }

  #[test]
  fn remove_factors_test() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
      crate::setup::factors::password("password4", PasswordOptions {
        id: Some("password4".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;
    let key = setup_key.key.clone();

    let derive1 = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password4".to_string(), derive_factors::password("password4")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive1.key, key);

    let derive2 = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password2".to_string(), derive_factors::password("password2")?),
        ("password3".to_string(), derive_factors::password("password3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive2.key, key);

    setup_key.remove_factors(&["password1", "password4"])?;

    let result = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password4".to_string(), derive_factors::password("password4")?),
      ]),
      false,
      false,
    );
    assert!(result.is_err(), "Derivation should fail after removing password1 and password4");

    let derive3 = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password2".to_string(), derive_factors::password("password2")?),
        ("password3".to_string(), derive_factors::password("password3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive3.key, key);

    Ok(())
  }

  #[test]
  fn add_factor() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key.add_factor(crate::setup::factors::password("password3", PasswordOptions {
      id: Some("password3".to_string()),
    })?)?;

    let derive = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password2".to_string(), derive_factors::password("password2")?),
        ("password3".to_string(), derive_factors::password("password3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive.key, key);

    Ok(())
  }

  #[test]
  fn add_factors() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key.add_factors(&[
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
      crate::setup::factors::password("password4", PasswordOptions {
        id: Some("password4".to_string()),
      })?,
    ])?;

    let derive = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password3".to_string(), derive_factors::password("password3")?),
        ("password4".to_string(), derive_factors::password("password4")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive.key, key);

    Ok(())
  }

  #[test]
  fn recover_factor() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key
      .recover_factor(crate::setup::factors::password("differentPassword3", PasswordOptions {
        id: Some("password3".to_string()),
      })?)?;

    let derive = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password3".to_string(), derive_factors::password("differentPassword3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive.key, key);

    Ok(())
  }

  #[test]
  fn recover_factors() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key.recover_factors(&[
      crate::setup::factors::password("differentPassword3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
      crate::setup::factors::password("otherPassword1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
    ])?;

    let derive = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password1".to_string(), derive_factors::password("otherPassword1")?),
        ("password3".to_string(), derive_factors::password("differentPassword3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive.key, key);

    Ok(())
  }

  #[test]
  fn reconstitute() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key.reconstitute(
      &["password1"],
      &[crate::setup::factors::password("otherPassword2", PasswordOptions {
        id: Some("password2".to_string()),
      })?],
      Some(2),
    )?;

    let derive = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password2".to_string(), derive_factors::password("otherPassword2")?),
        ("password3".to_string(), derive_factors::password("password3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive.key, key);

    Ok(())
  }

  #[test]
  fn defaults() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key.reconstitute(&[], &[], None)?;

    let derive = derive::key(
      &setup_key.policy,
      HashMap::from([
        ("password2".to_string(), derive_factors::password("password2")?),
        ("password3".to_string(), derive_factors::password("password3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive.key, key);

    Ok(())
  }

  #[test]
  fn remove_missing_factor() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;

    let result = setup_key.reconstitute(
      &["password4"],
      &[crate::setup::factors::password("otherPassword2", PasswordOptions {
        id: Some("password2".to_string()),
      })?],
      Some(2),
    );

    assert!(matches!(result, Err(error::MFKDF2Error::MissingFactor(id)) if id == "password4"));

    Ok(())
  }

  #[test]
  fn add_factor_unique_id() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;

    let result = setup_key.reconstitute(
      &["password3"],
      &[
        crate::setup::factors::password("otherPassword2", PasswordOptions {
          id: Some("password2".to_string()),
        })?,
        crate::setup::factors::password("diffPassword2", PasswordOptions {
          id: Some("password2".to_string()),
        })?,
      ],
      None,
    );

    assert!(matches!(result, Err(error::MFKDF2Error::DuplicateFactorId)));

    Ok(())
  }

  #[test]
  fn invalid_threshold() -> Result<(), error::MFKDF2Error> {
    let setup_factors = vec![
      crate::setup::factors::password("password1", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      crate::setup::factors::password("password2", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      crate::setup::factors::password("password3", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ];

    let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
    let mut setup_key = setup::key(&setup_factors, options)?;

    let result = setup_key.reconstitute(&["password1", "password2", "password3"], &[], Some(4));
    assert!(matches!(result, Err(error::MFKDF2Error::InvalidThreshold)));

    Ok(())
  }
}
