use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use zxcvbn::zxcvbn;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::MFKDF2Factor,
};

#[derive(uniffi::Record)]
pub struct PasswordOptions {
  pub id: Option<String>,
}

#[uniffi::export]
pub fn password_fn(password: &str, options: PasswordOptions) -> MFKDF2Result<MFKDF2Factor> {
  if password.is_empty() {
    return Err(MFKDF2Error::PasswordEmpty);
  }
  let strength = zxcvbn(password, &[]);

  // per-factor salt
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    kind:    "password".to_string(),
    id:      options.id.unwrap_or("password".to_string()),
    data:    password.as_bytes().to_vec(),
    salt:    salt.to_vec(),
    params:  json!({}).to_string(),
    entropy: Some(strength.guesses().ilog2()),
    output:  json!({}).to_string(),
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
