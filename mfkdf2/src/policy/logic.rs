use sha2::{Digest, Sha256};

use crate::{definitions::MFKDF2Factor, error::MFKDF2Result, setup::factors::stack::StackOptions};

#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_at_least"))]
pub async fn at_least(n: u8, factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  // Deterministic stack id based on threshold and sorted child ids
  let mut child_ids: Vec<String> =
    factors.iter().map(|f| f.id.clone().unwrap_or_default()).collect();
  child_ids.sort();
  let seed = format!("{}:{}", n, child_ids.join(","));
  let mut hasher = Sha256::new();
  hasher.update(seed.as_bytes());
  let hash = hasher.finalize();
  let id = format!("stack-{:x}", u64::from_be_bytes(<[u8; 8]>::try_from(&hash[..8]).unwrap()));
  let options = StackOptions { id: Some(id), threshold: Some(n), salt: None };
  crate::setup::factors::stack(factors, options)
}

#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_or"))]
pub async fn or(factor1: MFKDF2Factor, factor2: MFKDF2Factor) -> MFKDF2Result<MFKDF2Factor> {
  at_least(1, vec![factor1, factor2]).await
}

#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_and"))]
pub async fn and(factor1: MFKDF2Factor, factor2: MFKDF2Factor) -> MFKDF2Result<MFKDF2Factor> {
  at_least(2, vec![factor1, factor2]).await
}

#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_all"))]
pub async fn all(factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  let n = factors.len() as u8;
  at_least(n, factors).await
}

#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_any"))]
pub async fn any(factors: Vec<MFKDF2Factor>) -> MFKDF2Result<MFKDF2Factor> {
  at_least(1, factors).await
}
