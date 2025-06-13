use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;
use zxcvbn::{Entropy, zxcvbn};

use super::FactorMaterial;
use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::Factor,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[derive(Serialize, Deserialize)]
pub struct Password(String);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl Password {
  #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
  pub fn new(password: String) -> Password { Password(password) }

  #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
  pub fn factor(self) -> MFKDF2Result<JsValue> {
    let factor = self.into_factor()?;
    to_value(&factor).map_err(|_| MFKDF2Error::SerializeFactor)
  }
}

impl<T> From<T> for Password
where T: Into<String>
{
  fn from(password: T) -> Self { Self(password.into()) }
}

impl FactorMaterial for Password {
  type Output = Entropy;
  type Params = ();

  fn into_factor(self) -> MFKDF2Result<Factor<Self>> {
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
  #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
  fn test_password_strength() -> MFKDF2Result<()> {
    let password = Password::new("password".to_string());
    let factor = password.into_factor()?;
    assert_eq!(factor.output.score(), Score::Zero);

    let password = Password::new("98p23uijafjj--ah77yhfraklhjaza!?a3".to_string());
    let factor = password.into_factor()?;
    assert_eq!(factor.output.score(), Score::Four);

    Ok(())
  }
}
