use serde_json::json;
use zxcvbn::{Score, zxcvbn};

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::Material,
};

pub struct Password {
  password: String,
  score:    Score,
  entropy:  u32,
}

impl Password {
  // Creates a password from a string that cannot be empty.
  pub fn new(password: impl Into<String>) -> MFKDF2Result<Self> {
    let password = std::convert::Into::<String>::into(password);
    if password.is_empty() {
      return Err(MFKDF2Error::PasswordEmpty);
    }
    let strength = zxcvbn(&password, &[]);
    Ok(Self { password, score: strength.score(), entropy: strength.guesses().ilog2() })
  }
}

impl From<Password> for Material {
  fn from(password: Password) -> Self {
    Self {
      id:      None,
      kind:    "password".to_string(),
      data:    password.password.as_bytes().to_vec(),
      output:  json!({ "score": password.score }),
      entropy: password.entropy,
    }
  }
}

#[cfg(test)]
mod tests {
  use zxcvbn::Score;

  use super::*;

  #[test]
  fn test_password_strength() {
    let password = Password::new("password");
    let factor: Material = password.unwrap().into();
    assert_eq!(factor.output, json!({ "score": Score::Zero }));
    assert_eq!(factor.entropy, 1);

    let password = Password::new("98p23uijafjj--ah77yhfraklhjaza!?a3");
    let factor: Material = password.unwrap().into();
    assert_eq!(factor.output, json!({ "score": Score::Four }));
    assert_eq!(factor.entropy, 63);
  }
}
