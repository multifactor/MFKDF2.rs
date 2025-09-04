use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use zxcvbn::{Score, zxcvbn};

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::MFKDF2Factor,
};

pub struct Password {
  password: String,
  score:    Score,
  entropy:  u32,
}

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
