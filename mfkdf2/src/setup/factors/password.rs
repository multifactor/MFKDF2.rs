use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use zxcvbn::zxcvbn;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::MFKDF2Factor,
};

pub struct PasswordOptions {
  pub id: Option<String>,
}

pub fn password(
  password: impl Into<String>,
  options: Option<PasswordOptions>,
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
    id: options.unwrap_or(PasswordOptions { id: None }).id.unwrap_or("password".to_string()),
    data: password.as_bytes().to_vec(),
    salt,
    params: Some(Box::new(|| Box::pin(async { json!({}) }))),
    entropy: Some(strength.guesses().ilog2()),
    output: None,
  })
}

#[cfg(test)]
mod tests {

  use super::*;

  #[tokio::test]
  async fn test_password_strength() {
    let factor = password("password", None).unwrap();
    assert_eq!(factor.entropy, Some(1));

    let factor = password("98p23uijafjj--ah77yhfraklhjaza!?a3", None).unwrap();
    assert_eq!(factor.entropy, Some(63));
  }
}
