use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorSetupTrait, FactorSetupType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Password {
  pub password: String,
}

impl FactorSetupTrait for Password {
  fn kind(&self) -> String { "password".to_string() }

  fn bytes(&self) -> Vec<u8> { self.password.as_bytes().to_vec() }

  fn params_setup(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output_setup(&self, _key: [u8; 32]) -> Value {
    json!({
      "strength": zxcvbn(&self.password, &[]),
    })
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct PasswordOptions {
  pub id: Option<String>,
}

pub fn password(
  password: impl Into<String>,
  options: PasswordOptions,
) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }

  let password = std::convert::Into::<String>::into(password);
  if password.is_empty() {
    return Err(MFKDF2Error::PasswordEmpty);
  }
  let strength = zxcvbn(&password, &[]);

  // per-factor salt
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    id:          Some(options.id.unwrap_or("password".to_string())),
    factor_type: FactorSetupType::Password(Password { password }),
    salt:        salt.to_vec(),
    entropy:     Some(strength.guesses().ilog2()),
  })
}

#[uniffi::export]
pub fn setup_password(password: String, options: PasswordOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Reuse the existing constructor logic
  crate::setup::factors::password::password(password, options)
}

#[cfg(test)]
mod tests {

  use super::*;

  #[tokio::test]
  async fn test_password_strength() {
    let factor = password("password", PasswordOptions { id: None }).unwrap();
    assert_eq!(factor.entropy, Some(1));

    let factor =
      password("98p23uijafjj--ah77yhfraklhjaza!?a3", PasswordOptions { id: None }).unwrap();
    assert_eq!(factor.entropy, Some(63));
  }
}
