use std::rc::Rc;

use serde_json::json;
pub use uuid::Uuid;

use crate::{
  derive::{DeriveFactorFn, factors::MFKDF2DerivedFactor},
  error::MFKDF2Result,
};

pub fn uuid(uuid: Uuid) -> MFKDF2Result<DeriveFactorFn> {
  Ok(Rc::new(move |_params| {
    Box::pin(async move {
      Ok(MFKDF2DerivedFactor {
        kind:   "uuid".to_string(),
        data:   uuid.to_string().as_bytes().to_vec(),
        params: None,
        output: Some(Box::new(move |_| {
          Box::pin(async move { json!({ "uuid": uuid.to_string() }) })
        })),
      })
    })
  }))
}
