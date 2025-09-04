use serde_json::json;
use zxcvbn::zxcvbn;

use crate::{
  derive::factors::MFKDF2DerivedFactor,
  error::{MFKDF2Error, MFKDF2Result},
};

pub async fn password(password: impl Into<String>) -> MFKDF2Result<MFKDF2DerivedFactor> {
  let password = std::convert::Into::<String>::into(password);
  if password.is_empty() {
    return Err(MFKDF2Error::PasswordEmpty);
  }
  let strength = zxcvbn(&password, &[]);
  let strength = strength.guesses().ilog2();

  Ok(MFKDF2DerivedFactor {
    kind:   "password".to_string(),
    data:   password.as_bytes().to_vec(),
    params: None,
    output: Some(Box::pin(move || Box::pin(async move { json!({ "strength": strength }) }))),
  })
}
