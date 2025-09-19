use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  derive::{FactorDeriveTrait, factors::MFKDF2DeriveFactor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorType, password::Password},
};

impl FactorDeriveTrait for Password {
  fn kind(&self) -> String { "password".to_string() }

  fn bytes(&self) -> Vec<u8> { self.password.as_bytes().to_vec() }

  fn include_params(&mut self, _params: Value) -> MFKDF2Result<()> { Ok(()) }

  fn params_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output_derive(&self, _key: [u8; 32]) -> Value {
    json!({"strength": zxcvbn(&self.password, &[])})
  }
}

pub fn password(password: impl Into<String>) -> MFKDF2Result<MFKDF2DeriveFactor> {
  let password = std::convert::Into::<String>::into(password);
  if password.is_empty() {
    return Err(MFKDF2Error::PasswordEmpty);
  }
  let strength = zxcvbn(&password, &[]);
  let strength = strength.guesses().ilog2();

  Ok(MFKDF2DeriveFactor {
    factor_type: FactorType::Password(Password { password }),
    // TODO (autoparallel): This is confusing, should probably put an Option here. This pattern
    // appears in other factors and it's because of the refactoring done. The factors have a
    // "state" assiociated to them basically (in that they are "setup" or not).
    salt:        [0u8; 32].to_vec(),
    entropy:     Some(strength),
    id:          None,
  })
}

#[uniffi::export]
pub fn derive_password(password: String) -> MFKDF2Result<MFKDF2DeriveFactor> {
  crate::derive::factors::password::password(password)
}
