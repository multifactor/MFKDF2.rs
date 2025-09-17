use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};
pub use uuid::Uuid;

use crate::{error::MFKDF2Result, setup::factors::MFKDF2Factor};

pub struct UUIDOptions {
  pub id: Option<String>,
}

pub fn uuid(uuid: Uuid, options: UUIDOptions) -> MFKDF2Result<MFKDF2Factor> {
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    id: options.id.unwrap_or("uuid".to_string()),
    kind: "uuid".to_string(),
    data: uuid.to_string().as_bytes().to_vec(),
    salt,
    params: Some(Box::new(move |_| Box::pin(async move { json!({}) }))),
    output: Some(Box::new(move |_| Box::pin(async move { Value::String(uuid.to_string()) }))),

    entropy: Some(122),
  })
}
