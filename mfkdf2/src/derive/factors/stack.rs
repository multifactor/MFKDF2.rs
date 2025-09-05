use std::collections::HashMap;

use crate::{
  derive::{DeriveFactorFn, factors::MFKDF2DerivedFactor},
  error::MFKDF2Result,
  setup::key::Policy,
};

pub fn password(factors: HashMap<&str, DeriveFactorFn>) -> MFKDF2Result<DeriveFactorFn> {
  Ok(Box::new(move |params| {
    Box::pin(async move {
      let policy = serde_json::from_value::<Policy>(params).unwrap();
      let key = crate::derive::key(policy, factors.clone()).await?;
      Ok(MFKDF2DerivedFactor {
        kind:   "stack".to_string(),
        data:   key.key.to_vec(),
        params: Some(Box::new(move || {
          Box::pin(async move { serde_json::to_value(key.policy.clone()).unwrap() })
        })),
        output: Some(Box::new(move || Box::pin(async move { serde_json::to_value(key).unwrap() }))),
      })
    })
  }))
}
