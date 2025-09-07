use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::MFKDF2Factor,
};

#[derive(Debug, Serialize, Deserialize)]
pub enum FactorType {
  Password(Password),
}

impl FactorTrait for FactorType {
  fn bytes(&self) -> Vec<u8> {
    match self {
      FactorType::Password(password) => password.bytes(),
    }
  }

  fn params(&self, key: [u8; 32]) -> Value {
    match self {
      FactorType::Password(password) => password.params(key),
    }
  }

  fn output(&self, key: [u8; 32]) -> Value {
    match self {
      FactorType::Password(password) => password.output(key),
    }
  }
}

pub trait FactorTrait {
  fn bytes(&self) -> Vec<u8>;
  fn params(&self, key: [u8; 32]) -> Value;
  fn output(&self, key: [u8; 32]) -> Value;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Password {
  pub password: String,
}

impl FactorTrait for Password {
  fn bytes(&self) -> Vec<u8> { self.password.as_bytes().to_vec() }

  fn params(&self, key: [u8; 32]) -> Value { json!({}) }

  fn output(&self, key: [u8; 32]) -> Value { json!({}) }
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
    kind: "password".to_string(),
    id: options.id.unwrap_or("password".to_string()),
    data: FactorType::Password(Password { password }),
    salt,
    entropy: Some(strength.guesses().ilog2()),
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
