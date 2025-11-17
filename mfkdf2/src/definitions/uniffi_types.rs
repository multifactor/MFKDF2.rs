use jsonwebtoken::jwk::Jwk;
use serde_json::Value;
use uuid::Uuid;

use crate::{
  definitions::key::Key, error::MFKDF2Error, setup::factors::hmacsha1::HmacSha1Response,
};

uniffi::custom_type!(HmacSha1Response, Vec<u8>, {
  lower: |r| r.0.to_vec(),
  try_lift: |v: Vec<u8>| {
    if v.len() == 20 {
      let mut arr = [0u8; 20];
      arr.copy_from_slice(&v);
      Ok(HmacSha1Response(arr))
    } else {
      Err(uniffi::deps::anyhow::anyhow!(
        "Expected Vec<u8> of length 20, got {}",
        v.len()
      ))
    }
  }
});

uniffi::custom_type!(Jwk, String, {
  remote,
  lower: |v| serde_json::to_string(&v).expect("serialize Jwk"),
  try_lift: |s: String| Ok(serde_json::from_str(&s)?),
});

uniffi::custom_type!(Uuid, String, {
  remote,
  lower: |v| v.to_string(),
  try_lift: |s: String| Uuid::parse_str(&s).map_err(|_| MFKDF2Error::InvalidUuid).map_err(Into::into),
});

uniffi::custom_type!(Value, String, {
  remote,
  lower: |v| serde_json::to_string(&v).expect("serialize Value"),
  try_lift: |s: String| Ok(serde_json::from_str(&s)?),
});

// Uniffi custom type for Key
uniffi::custom_type!(Key, Vec<u8>);
