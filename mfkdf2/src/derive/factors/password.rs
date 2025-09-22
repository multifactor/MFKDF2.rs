use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{Factor, FactorType, MFKDF2Factor, password::Password},
};
impl FactorDerive for Password {
  fn include_params(&mut self, _params: Value) -> MFKDF2Result<()> { Ok(()) }

  fn params_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn output_derive(&self, _key: [u8; 32]) -> Value {
    json!({"strength": zxcvbn(&self.password, &[])})
  }
}

impl Factor for Password {}

pub fn password(password: impl Into<String>) -> MFKDF2Result<MFKDF2Factor> {
  let password = std::convert::Into::<String>::into(password);
  if password.is_empty() {
    return Err(MFKDF2Error::PasswordEmpty);
  }
  let strength = zxcvbn(&password, &[]);
  let strength = strength.guesses().ilog2();

  Ok(MFKDF2Factor {
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
pub fn derive_password(password: String) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::password::password(password)
}
