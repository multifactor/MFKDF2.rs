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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_uuid_factor() {
    let uuid = Uuid::from_u128(1234567890);
    let factor = uuid.material().unwrap();
    assert_eq!(factor.id, "uuid");
    assert_eq!(factor.data, uuid);
    assert_eq!(factor.output, uuid);
  }
}
