use uuid::Uuid;

use crate::{
  definitions::factor::MFKDF2Factor, error::MFKDF2Result, setup::factors::stack::StackOptions,
};

#[uniffi::export(name = "policy_at_least")]
pub async fn at_least(n: u8, factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  let id = Uuid::new_v4().to_string();
  let options = StackOptions { id: Some(id), threshold: Some(n), salt: None };
  crate::setup::factors::stack(factors, options)
}

#[uniffi::export(name = "policy_or")]
pub async fn or(factor1: MFKDF2Factor, factor2: MFKDF2Factor) -> MFKDF2Result<MFKDF2Factor> {
  at_least(1, vec![factor1, factor2]).await
}

#[uniffi::export(name = "policy_and")]
pub async fn and(factor1: MFKDF2Factor, factor2: MFKDF2Factor) -> MFKDF2Result<MFKDF2Factor> {
  at_least(2, vec![factor1, factor2]).await
}

#[uniffi::export(name = "policy_all")]
pub async fn all(factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  let n = factors.len() as u8;
  at_least(n, factors).await
}

#[uniffi::export(name = "policy_any")]
pub async fn any(factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  at_least(1, factors).await
}
