use crate::error::MFKDF2Result;

pub mod password;
pub mod question;
pub mod uuid;

pub trait FactorMaterial {
  type Params;
  type Output;
  fn material(input: Self) -> MFKDF2Result<Factor<Self>>
  where Self: Sized;
}

/// A scaffold for a factor in the MFKDF2 algorithm.
pub struct Factor<T: FactorMaterial> {
  pub id:     String,
  pub data:   T,
  pub params: T::Params,
  pub output: T::Output,
}
