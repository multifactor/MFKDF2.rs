use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  definitions::key::Key,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorMetadata, FactorSetup, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Password {
  pub password: String,
}

impl FactorMetadata for Password {
  fn kind(&self) -> String { "password".to_string() }
}

impl FactorSetup for Password {
  fn bytes(&self) -> Vec<u8> { self.password.as_bytes().to_vec() }

  fn params(&self, _key: Key) -> Value { json!({}) }

  fn output(&self, _key: Key) -> Value {
    json!({
      "strength": zxcvbn(&self.password, &[]),
    })
  }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, uniffi::Record)]
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
    factor_type: FactorType::Password(Password { password }),
    salt:        salt.to_vec(),
    entropy:     Some(strength.guesses().ilog2() as f64),
  })
}

#[uniffi::export]
pub async fn setup_password(
  password: String,
  options: PasswordOptions,
) -> MFKDF2Result<MFKDF2Factor> {
  // Reuse the existing constructor logic
  crate::setup::factors::password::password(password, options)
}

#[cfg(test)]
mod tests {

  use serde_json::json;

  use super::*;
  use crate::{error::MFKDF2Error, setup::factors::FactorSetup};

  #[test]
  fn password_strength() {
    let factor = password("password", PasswordOptions { id: None }).unwrap();
    assert_eq!(factor.entropy, Some(1.0));

    let factor =
      password("98p23uijafjj--ah77yhfraklhjaza!?a3", PasswordOptions { id: None }).unwrap();
    assert_eq!(factor.entropy, Some(63.0));
  }

  #[test]
  fn password_empty() {
    let err = password("", PasswordOptions { id: None }).unwrap_err();
    assert!(matches!(err, MFKDF2Error::PasswordEmpty));
  }

  #[test]
  fn password_empty_id() {
    let err = password("password", PasswordOptions { id: Some("".to_string()) }).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingFactorId));
  }

  #[test]
  fn password_valid() {
    let factor = password("hello", PasswordOptions { id: None }).unwrap();
    assert_eq!(factor.id, Some("password".to_string()));
    match &factor.factor_type {
      FactorType::Password(p) => {
        assert_eq!(p.password, "hello");
        assert_eq!(p.bytes(), "hello".as_bytes());
        let params = p.params([0; 32].into());
        assert_eq!(params, json!({}));
      },
      _ => panic!("Wrong factor type"),
    }
  }
}
