use uuid::Uuid;

use crate::{
  error::MFKDF2Result,
  setup::factors::{
    MFKDF2Factor,
    stack::{StackOptions, stack},
  },
};

#[uniffi::export]
pub async fn at_least(n: u8, factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  let id = Uuid::new_v4().to_string();
  let options = StackOptions { id: Some(id), threshold: Some(n), salt: None };
  stack(factors, options).await
}

#[uniffi::export]
pub async fn or(factor1: MFKDF2Factor, factor2: MFKDF2Factor) -> MFKDF2Result<MFKDF2Factor> {
  at_least(1, vec![factor1, factor2]).await
}

#[uniffi::export]
pub async fn and(factor1: MFKDF2Factor, factor2: MFKDF2Factor) -> MFKDF2Result<MFKDF2Factor> {
  at_least(2, vec![factor1, factor2]).await
}

#[uniffi::export]
pub async fn all(factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  let n = factors.len() as u8;
  at_least(n, factors).await
}

#[uniffi::export]
pub async fn any(factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  at_least(1, factors).await
}
