use std::{collections::HashMap, rc::Rc};

use crate::{
  derive::{DeriveFactorFn, factors::MFKDF2DerivedFactor},
  error::MFKDF2Result,
  setup::key::Policy,
};

pub fn stack(factors: HashMap<String, DeriveFactorFn>) -> MFKDF2Result<DeriveFactorFn> {
  Ok(Rc::new(move |params| {
    let factors = factors.clone();
    Box::pin(async move {
      let policy = serde_json::from_value::<Policy>(params).unwrap();
      let key = crate::derive::key(policy, factors).await?;

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
