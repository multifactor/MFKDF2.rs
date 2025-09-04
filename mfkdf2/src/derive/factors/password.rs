use std::pin::Pin;

use serde_json::json;
use zxcvbn::{Score, zxcvbn};

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

// pub struct Password {
//   password: String,
//   score:    Score,
//   entropy:  u32,
// }

// impl Password {
//   // Creates a password from a string that cannot be empty.
//   pub fn new(password: impl Into<String>) -> MFKDF2Result<Self> {
//     let password = std::convert::Into::<String>::into(password);
//     if password.is_empty() {
//       return Err(MFKDF2Error::PasswordEmpty);
//     }
//     let strength = zxcvbn(&password, &[]);
//     Ok(Self { password, score: strength.score(), entropy: strength.guesses().ilog2() })
//   }
// }

// impl From<Password> for Material {
//   fn from(password: Password) -> Self {
//     Self {
//       id:      None,
//       kind:    "password".to_string(),
//       data:    password.password.as_bytes().to_vec(),
//       output:  json!({ "score": password.score }),
//       entropy: password.entropy,
//     }
//   }
// }

// #[cfg(test)]
// mod tests {
//   use zxcvbn::Score;

//   use super::*;

//   #[test]
//   fn test_password_strength() {
//     let password = Password::new("password");
//     let factor: Material = password.unwrap().into();
//     assert_eq!(factor.output, json!({ "score": Score::Zero }));
//     assert_eq!(factor.entropy, 1);

//     let password = Password::new("98p23uijafjj--ah77yhfraklhjaza!?a3");
//     let factor: Material = password.unwrap().into();
//     assert_eq!(factor.output, json!({ "score": Score::Four }));
//     assert_eq!(factor.entropy, 63);
//   }
// }
