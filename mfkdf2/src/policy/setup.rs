use serde::{Deserialize, Serialize};

use crate::{
  definitions::{MFKDF2DerivedKey, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::key::{MFKDF2Options, key as setup_key},
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicySetupOptions {
  pub id:        Option<String>,
  pub threshold: Option<u8>,
  pub integrity: Option<bool>,
  pub salt:      Option<Vec<u8>>,
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

pub fn setup(factor: MFKDF2Factor, options: PolicySetupOptions) -> MFKDF2Result<MFKDF2DerivedKey> {
  let derived_key = setup_key(&[factor], options.into())?;

  if !derived_key.policy.validate() {
    return Err(MFKDF2Error::DuplicateFactorId);
  }

  Ok(derived_key)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn policy_setup(
  factor: MFKDF2Factor,
  options: PolicySetupOptions,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  setup(factor, options)
}
