use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorTrait, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Password {
  pub password: String,
}

impl FactorTrait for Password {
  fn kind(&self) -> String { "password".to_string() }

  fn bytes(&self) -> Vec<u8> { self.password.as_bytes().to_vec() }

  fn params_setup(&self, key: [u8; 32]) -> Value { json!({}) }

  fn output_setup(&self, key: [u8; 32]) -> Value { json!({}) }

  fn params_derive(&self, key: [u8; 32]) -> Value { json!({}) }

  fn output_derive(&self, key: [u8; 32]) -> Value { json!({}) }

  fn include_params(&mut self, params: Value) {}
}

pub struct PasswordOptions {
  pub id: Option<String>,
}

pub fn password(
  password: impl Into<String>,
  options: PasswordOptions,
) -> MFKDF2Result<MFKDF2Factor> {
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
    factor_type: FactorType::Password(Password { password }),
    salt:        salt.to_vec(),
    entropy:     Some(strength.guesses().ilog2()),
    // inner: Some(Box::new(Password {})),
  })
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
