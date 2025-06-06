use crate::{error::MFKDF2Result, factors::Factor};

use super::FactorMaterial;
use uuid::Uuid;

impl FactorMaterial for Uuid {
  type Params = ();
  type Output = Self;

  fn material(input: Self) -> MFKDF2Result<Factor<Self>> {
    Ok(Factor { id: "uuid".to_string(), data: input, params: (), output: input })
  }
}
