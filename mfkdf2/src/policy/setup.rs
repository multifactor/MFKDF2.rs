use serde::{Deserialize, Serialize};

use crate::{
  definitions::mfkdf_derived_key::MFKDF2DerivedKey,
  error::{MFKDF2Error, MFKDF2Result},
  setup::{
    factors::MFKDF2Factor,
    key::{MFKDF2Options, key as setup_key},
  },
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record, Default)]
pub struct PolicySetupOptions {
  pub id:        Option<String>,
  pub threshold: Option<u8>,
  pub integrity: Option<bool>,
  pub salt:      Option<Vec<u8>>,
}

impl From<PolicySetupOptions> for MFKDF2Options {
  fn from(value: PolicySetupOptions) -> Self {
    MFKDF2Options {
      id: value.id,
      threshold: value.threshold,
      integrity: value.integrity,
      salt: value.salt,
      ..Default::default()
    }
  }
}

#[uniffi::export(name = "policy_setup")]
pub async fn setup(
  factor: MFKDF2Factor,
  options: PolicySetupOptions,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let derived_key = setup_key(vec![factor], options.into()).await?;

  if !derived_key.policy.validate() {
    return Err(MFKDF2Error::DuplicateFactorId);
  }

  Ok(derived_key)
}
