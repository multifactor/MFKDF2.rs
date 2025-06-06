use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::Factor,
};

use super::FactorMaterial;
use zxcvbn::{Entropy, zxcvbn};

pub struct Password(String);

impl FactorMaterial for Password {
  type Params = ();
  type Output = Entropy;

  fn material(input: Self) -> MFKDF2Result<Factor<Self>> {
    if input.0.is_empty() {
      return Err(MFKDF2Error::PasswordEmpty);
    }

    let strength = zxcvbn(&input.0, &[]);
    Ok(Factor { id: "password".to_string(), data: input, params: (), output: strength })
  }
}
