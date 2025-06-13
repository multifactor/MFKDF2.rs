use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")] use wasm_bindgen::prelude::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[derive(Clone, Serialize, Deserialize)]
pub struct Uuid(uuid::Uuid);

use super::FactorMaterial;
use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::Factor,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl Uuid {
  #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
  pub fn new(uuid: String) -> MFKDF2Result<Self> {
    Ok(Self(uuid::Uuid::parse_str(&uuid).map_err(|_| MFKDF2Error::UuidInvalid)?))
  }

  #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
  pub fn factor(self) -> MFKDF2Result<wasm_bindgen::JsValue> {
    let factor = self.into_factor()?;
    serde_wasm_bindgen::to_value(&factor).map_err(|_| MFKDF2Error::SerializeFactor)
  }
}

impl From<uuid::Uuid> for Uuid {
  fn from(uuid: uuid::Uuid) -> Self { Self(uuid) }
}

impl FactorMaterial for Uuid {
  type Output = Self;
  type Params = ();

  fn into_factor(self) -> MFKDF2Result<Factor<Self>> {
    Ok(Factor { id: "uuid".to_string(), data: self.clone(), params: (), output: self })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
  fn test_uuid_factor() -> MFKDF2Result<()> {
    let uuid = uuid::Uuid::from_u128(123_456_789_012);
    let uuid = Uuid(uuid);
    let factor = uuid.clone().into_factor()?;
    assert_eq!(factor.id, "uuid");
    assert_eq!(factor.data.0, uuid.0);
    assert_eq!(factor.output.0, uuid.0);

    Ok(())
  }
}
