use std::sync::Arc;

use rand::{Rng, rngs::OsRng};
use serde_json::{Value, json};

use crate::{
  derive::{DeriveFactorFn, factors::MFKDF2DerivedFactor},
  error::MFKDF2Result,
};

pub struct HMACSHA1Options {
  pub id:     Option<String>,
  pub secret: Option<[u8; 20]>,
}

pub fn hmacsha1(response: [u8; 20]) -> MFKDF2Result<DeriveFactorFn> {
  Ok(Arc::new(move |params: Value| {
    let pad: Vec<u8> =
      params["pad"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let secret: [u8; 20] = std::array::from_fn(|i| response[i] ^ pad[i]);

    Box::pin(async move {
      Ok(MFKDF2DerivedFactor {
        kind:   "hmacsha1".to_string(),
        data:   secret.to_vec(),
        params: Some(Box::new(move || {
          let challenge = OsRng.r#gen::<u64>();
          let response = crate::crypto::hmacsha1(&secret, challenge);
          let pad = response.iter().zip(secret.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
          Box::pin(async move { json!({ "challenge": challenge, "pad": pad }) })
        })),
        output: Some(Box::new(move || Box::pin(async move { json!({ "secret": secret }) }))),
      })
    })
  }))
}
