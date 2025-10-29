use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  definitions::{FactorType, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::password::Password,
};

impl FactorDerive for Password {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, _params: Self::Params) -> MFKDF2Result<()> { Ok(()) }

  fn output(&self) -> Self::Output { json!({"strength": zxcvbn(&self.password, &[])}) }
}

pub fn password(password: impl Into<String>) -> MFKDF2Result<MFKDF2Factor> {
  let password = std::convert::Into::<String>::into(password);
  if password.is_empty() {
    return Err(MFKDF2Error::PasswordEmpty);
  }
  let strength = zxcvbn(&password, &[]);
  let strength = strength.guesses().ilog2() as f64;

  Ok(MFKDF2Factor {
    factor_type: FactorType::Password(Password { password }),
    entropy:     Some(strength as f64),
    id:          None,
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn derive_password(password: String) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::password::password(password)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{error::MFKDF2Error, setup::FactorSetup};

  #[test]
  fn test_password_empty() {
    let err = password("").unwrap_err();
    assert!(matches!(err, MFKDF2Error::PasswordEmpty));
  }

  #[test]
  fn test_password_valid() {
    let factor = password("hello").unwrap();
    assert_eq!(factor.id, None);

    match &factor.factor_type {
      FactorType::Password(p) => {
        assert_eq!(p.password, "hello");
        assert_eq!(factor.data(), "hello".as_bytes());
        let params: Value = <Password as FactorSetup>::params(p, [0u8; 32].into()).unwrap();
        // TODO: fix this
        // let output = p.output_derive();
        // let strength: Entropy = serde_json::from_value(output["strength"].clone()).unwrap();
        // assert_eq!(strength.guesses().ilog2(), factor.entropy.unwrap());
        assert_eq!(params, json!({}));
      },
      _ => panic!("Wrong factor type"),
    }
  }
}
