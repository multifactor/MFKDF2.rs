use std::rc::Rc;

use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  derive::{DeriveFactorFn, factors::MFKDF2DerivedFactor},
  error::{MFKDF2Error, MFKDF2Result},
};

pub fn question(answer: impl Into<String>) -> MFKDF2Result<DeriveFactorFn> {
  let answer = answer.into();
  if answer.is_empty() {
    return Err(MFKDF2Error::AnswerEmpty);
  }
  let answer = answer.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "").trim().to_string();
  let strength = zxcvbn(&answer, &[]);

  Ok(Rc::new(move |params: Value| {
    let answer = answer.clone();
    let strength = strength.clone();
    Box::pin(async move {
      Ok(MFKDF2DerivedFactor {
        kind:   "question".to_string(),
        data:   answer.as_bytes().to_vec(),
        params: Some(Box::new(move |_| {
          let p = params.clone();
          Box::pin(async move { p })
        })),
        output: Some(Box::new(move |_| {
          let s = strength.clone();
          Box::pin(async move { json!({ "strength": s }) })
        })),
      })
    })
  }))
}
