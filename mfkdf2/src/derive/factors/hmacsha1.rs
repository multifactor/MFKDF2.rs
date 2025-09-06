use std::sync::Arc;

use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  derive::{DeriveFactorFn, factors::MFKDF2DerivedFactor},
  error::{MFKDF2Error, MFKDF2Result},
};

pub fn hmacsha1(answer: impl Into<String>) -> MFKDF2Result<DeriveFactorFn> {
  todo!();

  //   Ok(Arc::new(move |params: Value| {
  //     let answer = answer.clone();
  //     let strength = strength.clone();
  //     Box::pin(async move {
  //       Ok(MFKDF2DerivedFactor {
  //         kind:   "question".to_string(),
  //         data:   answer.as_bytes().to_vec(),
  //         params: Some(Box::new(move || {
  //           let p = params.clone();
  //           Box::pin(async move { p })
  //         })),
  //         output: Some(Box::new(move || {
  //           let s = strength.clone();
  //           Box::pin(async move { json!({ "strength": s }) })
  //         })),
  //       })
  //     })
  //   }))
}
