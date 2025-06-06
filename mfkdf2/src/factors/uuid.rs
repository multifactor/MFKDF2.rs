use uuid::Uuid;

use super::FactorMaterial;
use crate::{error::MFKDF2Result, factors::Factor};

impl FactorMaterial for Uuid {
  type Output = Self;
  type Params = ();

  fn material(input: Self) -> MFKDF2Result<Factor<Self>> {
    Ok(Factor { id: "uuid".to_string(), data: input, params: (), output: input })
  }
}
