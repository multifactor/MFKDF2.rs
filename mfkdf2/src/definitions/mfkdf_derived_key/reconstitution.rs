use std::collections::{HashMap, HashSet};

use base64::{Engine, engine::general_purpose};

use crate::{
  constants::SECRET_SHARING_POLY,
  crypto::{encrypt, hkdf_sha256_with_info, hmacsha256},
  definitions::{MFKDF2DerivedKey, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::{FactorSetup, key::PolicyFactor},
};

impl MFKDF2DerivedKey {
  pub fn set_threshold(&mut self, threshold: u8) -> MFKDF2Result<()> {
    self.reconstitute(&[], &[], Some(threshold))
  }

  pub fn remove_factor(&mut self, factor: &str) -> MFKDF2Result<()> {
    self.reconstitute(&[factor], &[], None)
  }

  pub fn remove_factors(&mut self, factors: &[&str]) -> MFKDF2Result<()> {
    self.reconstitute(factors, &[], None)
  }

  pub fn add_factor(&mut self, factor: MFKDF2Factor) -> MFKDF2Result<()> {
    self.reconstitute(&[], &[factor], None)
  }

  pub fn add_factors(&mut self, factors: &[MFKDF2Factor]) -> MFKDF2Result<()> {
    self.reconstitute(&[], factors, None)
  }

  pub fn recover_factor(&mut self, factor: MFKDF2Factor) -> MFKDF2Result<()> {
    self.reconstitute(&[], &[factor], None)
  }

  pub fn recover_factors(&mut self, factors: &[MFKDF2Factor]) -> MFKDF2Result<()> {
    self.reconstitute(&[], factors, None)
  }

  pub fn reconstitute(
    &mut self,
    remove_factor: &[&str],
    add_factor: &[MFKDF2Factor],
    threshold: Option<u8>,
  ) -> MFKDF2Result<()> {
    let mut factors = HashMap::new();
    let mut material: HashMap<String, [u8; 32]> = HashMap::new();
    let mut outputs = HashMap::new();
    let mut data = HashMap::new();

    let threshold = threshold.unwrap_or(self.policy.threshold);

    for factor in self.policy.factors.iter() {
      factors.insert(factor.id.clone(), factor.clone());

      let pad = general_purpose::STANDARD.decode(&factor.secret)?;
      let salt = general_purpose::STANDARD.decode(&factor.salt)?;
      let secret_key = hkdf_sha256_with_info(
        &self.key,
        &salt,
        format!("mfkdf2:factor:secret:{}", factor.id).as_bytes(),
      );
      let factor_material = crate::crypto::decrypt(pad, &secret_key);

      material.insert(
        factor.id.clone(),
        factor_material.try_into().map_err(|_| MFKDF2Error::TryFromVecError)?,
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
      crate::rng::det_rng::fill_bytes(&mut salt);

      let id = factor.id.clone().ok_or(MFKDF2Error::MissingFactorId)?;

      let params_key =
        hkdf_sha256_with_info(&self.key, &salt, format!("mfkdf2:factor:params:{}", id).as_bytes());
      let params = factor.factor_type.setup().params(params_key.into())?;

      let new_factor = PolicyFactor {
        id:     id.clone(),
        kind:   factor.kind(),
        salt:   general_purpose::STANDARD.encode(salt),
        params: serde_json::to_string(&params)?,
        hint:   None,
        pad:    "".to_string(),
        secret: "".to_string(),
      };

      factors.insert(id.clone(), new_factor);
      outputs
        .insert(id.clone(), factor.factor_type.output(self.key.clone().try_into()?).to_string());
      data.insert(id.clone(), factor.data());
      if material.contains_key(&id) {
        material.remove(&id);
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

    let dealer = ssskit::SecretSharing(threshold)
      .dealer_rng(&self.secret, &mut crate::rng::det_rng::GlobalRng);
    let shares: Vec<Vec<u8>> = dealer
      .take(factors.len())
      .map(|s: ssskit::Share<SECRET_SHARING_POLY>| Vec::from(&s))
      .collect();

    let mut new_factors = vec![];

    for (id, factor) in factors.values_mut().enumerate() {
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
        return Err(MFKDF2Error::TryFromVecError);
      };

      let secret_key = hkdf_sha256_with_info(
        &self.key,
        &salt,
        format!("mfkdf2:factor:secret:{}", factor.id).as_bytes(),
      );

      factor.pad = general_purpose::STANDARD.encode(encrypt(&shares[id], stretched));
      factor.secret = general_purpose::STANDARD.encode(encrypt(stretched, &secret_key));

      new_factors.push(factor.clone());
    }

    self.policy.factors = new_factors;
    self.policy.threshold = threshold;
    self.outputs = outputs;
    self.shares = shares;

    if !self.policy.hmac.is_empty() {
      let salt = general_purpose::STANDARD.decode(&self.policy.salt)?;
      let integrity_key = hkdf_sha256_with_info(&self.key, &salt, "mfkdf2:integrity".as_bytes());
      let integrity_data = self.policy.extract();
      let digest = hmacsha256(&integrity_key, &integrity_data);
      self.policy.hmac = general_purpose::STANDARD.encode(digest);
    }

    Ok(())
  }
}

// TODO (@lonerapier): this should take a mut reference to the derived key
#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_set_threshold(
  derived_key: MFKDF2DerivedKey,
  threshold: u8,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.set_threshold(threshold)?;
  Ok(derived_key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_remove_factor(
  derived_key: MFKDF2DerivedKey,
  factor: &str,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.remove_factor(factor)?;
  Ok(derived_key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_remove_factors(
  derived_key: MFKDF2DerivedKey,
  factors: &[String],
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.remove_factors(factors.iter().map(|f| f.as_str()).collect::<Vec<&str>>().as_ref())?;
  Ok(derived_key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_add_factor(
  derived_key: MFKDF2DerivedKey,
  factor: MFKDF2Factor,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.add_factor(factor)?;
  Ok(derived_key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_add_factors(
  derived_key: MFKDF2DerivedKey,
  factors: &[MFKDF2Factor],
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.add_factors(factors)?;
  Ok(derived_key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_recover_factor(
  derived_key: MFKDF2DerivedKey,
  factor: MFKDF2Factor,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.recover_factor(factor)?;
  Ok(derived_key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_recover_factors(
  derived_key: MFKDF2DerivedKey,
  factors: &[MFKDF2Factor],
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.recover_factors(factors)?;
  Ok(derived_key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_reconstitute(
  derived_key: MFKDF2DerivedKey,
  remove_factor: &[String],
  add_factor: &[MFKDF2Factor],
  threshold: Option<u8>,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut derived_key = derived_key;
  derived_key.reconstitute(
    remove_factor.iter().map(|f| f.as_str()).collect::<Vec<&str>>().as_ref(),
    add_factor,
    threshold,
  )?;
  Ok(derived_key)
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use crate::{
    derive, derive::factors as derive_factors, error, setup,
    setup::factors::password::PasswordOptions,
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

    let mut setup = setup::key(setup_factors, setup::key::MFKDF2Options {
      threshold: Some(3),
      integrity: Some(false),
      ..Default::default()
    })?;
    let setup_key = setup.key.clone();

    let derive_factors = HashMap::from([
      ("password1".to_string(), derive_factors::password("password1")?),
      ("password2".to_string(), derive_factors::password("password2")?),
    ]);

    let result = derive::key(setup.policy.clone(), derive_factors.clone(), false, false);
    assert!(result.is_err(), "Derivation should fail with threshold 3 and only 2 factors provided");

    setup.set_threshold(2)?;

    let derive = derive::key(setup.policy, derive_factors, false, false)?;

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

    let options = setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;
    let key = setup_key.key.clone();

    let derive1 = derive::key(
      setup_key.policy.clone(),
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
      setup_key.policy.clone(),
      HashMap::from([
        ("password2".to_string(), derive_factors::password("password2")?),
        ("password3".to_string(), derive_factors::password("password3")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive2.key, key);

    let result = derive::key(
      setup_key.policy.clone(),
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password2".to_string(), derive_factors::password("password2")?),
      ]),
      false,
      false,
    );
    assert!(result.is_err(), "Derivation should fail after removing password1");

    let result = derive::key(
      derive2.policy.clone(),
      HashMap::from([("password2".to_string(), derive_factors::password("password2")?)]),
      false,
      false,
    );
    assert!(result.is_err(), "Derivation should fail after removing password2 and threshold is 2");

    derive2.set_threshold(1)?;

    derive2.remove_factor("password2")?;

    let mut derive_factors3 = HashMap::new();
    derive_factors3.insert("password3".to_string(), derive_factors::password("password3")?);

    let derive3 = derive::key(derive2.policy.clone(), derive_factors3, false, false)?;
    assert_eq!(derive3.key, key);

    let result = derive::key(
      derive2.policy,
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

    let options = setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;
    let key = setup_key.key.clone();

    let derive1 = derive::key(
      setup_key.policy.clone(),
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password4".to_string(), derive_factors::password("password4")?),
      ]),
      false,
      false,
    )?;
    assert_eq!(derive1.key, key);

    let derive2 = derive::key(
      setup_key.policy.clone(),
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
      setup_key.policy.clone(),
      HashMap::from([
        ("password1".to_string(), derive_factors::password("password1")?),
        ("password4".to_string(), derive_factors::password("password4")?),
      ]),
      false,
      false,
    );
    assert!(result.is_err(), "Derivation should fail after removing password1 and password4");

    let derive3 = derive::key(
      setup_key.policy,
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

    let options = setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key.add_factor(crate::setup::factors::password("password3", PasswordOptions {
      id: Some("password3".to_string()),
    })?)?;

    let derive = derive::key(
      setup_key.policy.clone(),
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

    let options = setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;
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
      setup_key.policy.clone(),
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

    let options = setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key
      .recover_factor(crate::setup::factors::password("differentPassword3", PasswordOptions {
        id: Some("password3".to_string()),
      })?)?;

    let derive = derive::key(
      setup_key.policy.clone(),
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

    let options = setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;
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
      setup_key.policy.clone(),
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

    let options = setup::key::MFKDF2Options { threshold: Some(3), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key.reconstitute(
      &["password1"],
      &[crate::setup::factors::password("otherPassword2", PasswordOptions {
        id: Some("password2".to_string()),
      })?],
      Some(2),
    )?;

    let derive = derive::key(
      setup_key.policy.clone(),
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

    let options = setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;
    let key = setup_key.key.clone();

    setup_key.reconstitute(&[], &[], None)?;

    let derive = derive::key(
      setup_key.policy.clone(),
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

    let options = setup::key::MFKDF2Options { threshold: Some(3), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;

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

    let options = setup::key::MFKDF2Options { threshold: Some(3), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;

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

    let options = setup::key::MFKDF2Options { threshold: Some(3), ..Default::default() };
    let mut setup_key = setup::key(setup_factors, options)?;

    let result = setup_key.reconstitute(&["password1", "password2", "password3"], &[], Some(4));
    assert!(matches!(result, Err(error::MFKDF2Error::InvalidThreshold)));

    Ok(())
  }
}
