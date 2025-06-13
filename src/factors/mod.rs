use serde::{Deserialize, Serialize};

use crate::error::MFKDF2Result;

pub mod password;
pub mod question;
pub mod uuid;

pub trait FactorMaterial {
  type Params;
  type Output;
  fn into_factor(self) -> MFKDF2Result<Factor<Self>>
  where Self: Sized;
}

/// A scaffold for a factor in the MFKDF2 algorithm.
#[derive(Serialize, Deserialize)]
pub struct Factor<T: FactorMaterial> {
  pub id:     String,
  pub data:   T,
  pub params: T::Params,
  pub output: T::Output,
}
