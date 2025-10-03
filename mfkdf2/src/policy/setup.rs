use crate::{
  definitions::mfkdf_derived_key::MFKDF2DerivedKey,
  error::{MFKDF2Error, MFKDF2Result},
  setup::{
    factors::MFKDF2Factor,
    key::{MFKDF2Options, key as setup_key},
  },
};

#[uniffi::export(name = "policy_setup")]
pub async fn setup(factor: MFKDF2Factor, options: MFKDF2Options) -> MFKDF2Result<MFKDF2DerivedKey> {
  let derived_key = setup_key(vec![factor], options).await?;

  if !derived_key.policy.validate() {
    return Err(MFKDF2Error::DuplicateFactorId);
  }

  Ok(derived_key)
}
