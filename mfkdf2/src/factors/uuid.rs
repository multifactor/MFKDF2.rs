use uuid::Uuid;

use super::FactorMaterial;
use crate::{error::MFKDF2Result, factors::Factor};

impl FactorMaterial for Uuid {
  type Output = Self;
  type Params = ();

  fn material(self) -> MFKDF2Result<Factor<Self>> {
    Ok(Factor { id: "uuid".to_string(), data: self, params: (), output: self })
  }
}
