use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
  definitions::{FactorMetadata, FactorType, MFKDF2Factor},
  derive::FactorDerive,
  error::MFKDF2Result,
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Persisted {
  pub share: Vec<u8>,
}

impl FactorMetadata for Persisted {
  fn kind(&self) -> String { "persisted".to_string() }

  fn bytes(&self) -> Vec<u8> { self.share.clone() }
}

impl FactorDerive for Persisted {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, _params: Self::Params) -> MFKDF2Result<()> { Ok(()) }

  fn output(&self) -> Self::Output { Value::Null }
}

pub fn persisted(share: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> {
  Ok(MFKDF2Factor {
    id:          Some("persisted".to_string()),
    factor_type: FactorType::Persisted(Persisted { share }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_persisted(share: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> { persisted(share) }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn persisted_factor() {
    let share = vec![1, 2, 3];
    let factor = persisted(share.clone()).unwrap();
    let persisted = match factor.factor_type {
      FactorType::Persisted(persisted) => persisted,
      _ => panic!("Persisted factor should be created"),
    };
    assert_eq!(persisted.share, share);
  }
}
