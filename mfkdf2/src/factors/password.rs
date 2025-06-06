use zxcvbn::{Entropy, zxcvbn};

use super::FactorMaterial;
use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::Factor,
};

pub struct Password(String);

impl FactorMaterial for Password {
  type Output = Entropy;
  type Params = ();

  fn material(input: Self) -> MFKDF2Result<Factor<Self>> {
    if input.0.is_empty() {
      return Err(MFKDF2Error::PasswordEmpty);
    }

    let strength = zxcvbn(&input.0, &[]);
    Ok(Factor { id: "password".to_string(), data: input, params: (), output: strength })
  }
}
