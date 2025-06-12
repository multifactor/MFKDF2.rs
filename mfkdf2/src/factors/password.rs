use zxcvbn::{Entropy, zxcvbn};

use super::FactorMaterial;
use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::Factor,
};

pub struct Password(String);

impl Password {
  pub fn new(password: impl Into<String>) -> Self { Self(password.into()) }
}

impl FactorMaterial for Password {
  type Output = Entropy;
  type Params = ();

  fn material(self) -> MFKDF2Result<Factor<Self>> {
    if self.0.is_empty() {
      return Err(MFKDF2Error::PasswordEmpty);
    }

    let strength = zxcvbn(&self.0, &[]);
    Ok(Factor { id: "password".to_string(), data: self, params: (), output: strength })
  }
}

#[cfg(test)]
mod tests {
  use zxcvbn::Score;

  use super::*;

  #[test]
  fn test_password_strength() {
    let password = Password::new("password");
    let factor = password.material().unwrap();
    dbg!(factor.output.score());
    assert_eq!(factor.output.score(), Score::Zero);

    let password = Password::new("98p23uijafjj--ah77yhfraklhjaza!?a3");
    let factor = password.material().unwrap();
    dbg!(factor.output.score());
    assert_eq!(factor.output.score(), Score::Four);
  }
}
