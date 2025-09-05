use std::{collections::HashMap, sync::Arc};

use crate::{
  derive::{DeriveFactorFn, factors::MFKDF2DerivedFactor},
  error::MFKDF2Result,
  setup::key::Policy,
};

pub fn stack(factors: HashMap<String, DeriveFactorFn>) -> MFKDF2Result<DeriveFactorFn> {
  let factors = Arc::new(factors);
  Ok(Arc::new(move |params| {
    let factors = Arc::clone(&factors);
    Box::pin(async move {
      let policy = serde_json::from_value::<Policy>(params).unwrap();
      let key = crate::derive::key(policy, (*factors).clone()).await?;

      let policy = key.policy.clone();

      Ok(MFKDF2DerivedFactor {
        kind:   "stack".to_string(),
        data:   key.key.to_vec(),
        params: Some(Box::new(move || {
          let policy = policy.clone();
          Box::pin(async move { serde_json::to_value(policy).unwrap() })
        })),
        output: Some(Box::new(move || {
          let key = key.clone();
          Box::pin(async move { serde_json::to_value(key).unwrap() })
        })),
      })
    })
  }))
}
