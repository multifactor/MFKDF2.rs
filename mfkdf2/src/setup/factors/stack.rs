use rand::{RngCore, rngs::OsRng};

use crate::{
  error::MFKDF2Result,
  setup::{factors::MFKDF2Factor, key::MFKDF2Options},
};

pub async fn stack(
  factors: Vec<MFKDF2Factor>,
  options: MFKDF2Options,
) -> MFKDF2Result<MFKDF2Factor> {
  let key = crate::setup::key(factors, options.clone()).await?;

  // per-factor salt
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    // kind: "stack".to_string(),
    id: options.id.unwrap_or("stack".to_string()),
    // factor_type:
    data: key.key.to_vec(),
    salt,
    params: Some(Box::new(move |_| {
      let policy = key.policy.clone();
      Box::pin(async { serde_json::to_value(policy).unwrap() })
    })),
    entropy: Some(key.entropy.real),
    output: None,
  })
}
