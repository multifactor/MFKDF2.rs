use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  crypto::encrypt,
  error::MFKDF2Result,
  setup::factors::{FactorMetadata, FactorSetup, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct HmacSha1Options {
  pub id:     Option<String>,
  pub secret: Option<Vec<u8>>,
}

impl Default for HmacSha1Options {
  fn default() -> Self { Self { id: Some("hmacsha1".to_string()), secret: None } }
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct HmacSha1 {
  // TODO (@lonerapier): i don't like this, it should be a separate derive struct in derive module
  pub response:      Option<Vec<u8>>,
  pub params:        Option<String>,
  pub padded_secret: Vec<u8>,
}

impl FactorMetadata for HmacSha1 {
  fn kind(&self) -> String { "hmacsha1".to_string() }
}

impl FactorSetup for HmacSha1 {
  fn bytes(&self) -> Vec<u8> { self.padded_secret[..20].to_vec() }

  fn params(&self, _key: [u8; 32]) -> Value {
    let mut challenge = [0u8; 64];
    OsRng.fill_bytes(&mut challenge);

    let response = crate::crypto::hmacsha1(&self.padded_secret[..20], &challenge);
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(&response);
    let pad = encrypt(&self.padded_secret, &padded_key);

    json!({
      "challenge": challenge.to_vec(),
      "pad": pad,
    })
  }

  fn output(&self, _key: [u8; 32]) -> Value {
    json!({
      "secret": self.padded_secret[..20],
    })
  }
}

pub fn hmacsha1(options: HmacSha1Options) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }

  let secret = options.secret.unwrap_or_else(|| {
    let mut secret = [0u8; 20];
    OsRng.fill_bytes(&mut secret);
    secret.to_vec()
  });
  let mut secret_pad = [0u8; 12];
  OsRng.fill_bytes(&mut secret_pad);
  let padded_secret = secret.iter().chain(secret_pad.iter()).cloned().collect();

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    id:          Some(options.id.unwrap_or("hmacsha1".to_string())),
    salt:        salt.to_vec(),
    factor_type: FactorType::HmacSha1(HmacSha1 { padded_secret, response: None, params: None }),
    entropy:     Some(160),
  })
}

#[uniffi::export]
pub fn setup_hmacsha1(options: HmacSha1Options) -> MFKDF2Result<MFKDF2Factor> { hmacsha1(options) }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_hmacsha1_with_known_secret() {
    // Use a known secret for deterministic testing
    let known_secret = [
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14,
    ];

    let factor = hmacsha1(HmacSha1Options {
      id:     Some("test".to_string()),
      secret: Some(known_secret.to_vec()),
    })
    .unwrap();

    assert_eq!(factor.kind(), "hmacsha1");
    assert_eq!(factor.id.unwrap(), "test");
    assert_eq!(factor.factor_type.bytes(), known_secret.to_vec());

    // Get the challenge and pad from params
    let params = factor.factor_type.params([0u8; 32]);
    let challenge = params["challenge"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_u64().unwrap() as u8)
      .collect::<Vec<u8>>();
    let pad = params["pad"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_u64().unwrap() as u8)
      .collect::<Vec<u8>>();

    // Compute HMAC-SHA1 response externally to verify
    let expected_response = crate::crypto::hmacsha1(&known_secret, &challenge);

    // Verify the pad is correct (ENC(secret, key))
    let mut padded_secret = [0u8; 32];
    padded_secret[..known_secret.len()].copy_from_slice(&known_secret);

    let mut padded_key = [0u8; 32];
    padded_key[..expected_response.len()].copy_from_slice(&expected_response);

    let expected_pad = encrypt(&padded_secret, &padded_key);

    // verify partial pad (multiple of 16) is correct
    assert_eq!(pad[..16], expected_pad[..16]);
  }

  #[test]
  fn test_hmacsha1_random_secret() {
    let factor = hmacsha1(HmacSha1Options { id: None, secret: None }).unwrap();
    assert_eq!(factor.kind(), "hmacsha1");
    assert_eq!(factor.id.unwrap(), "hmacsha1");
    assert_eq!(factor.factor_type.bytes().len(), 20); // Secret should be 20 bytes
    assert!(factor.factor_type.params([0u8; 32]).is_object());
    assert!(factor.factor_type.output([0u8; 32]).is_object());
    assert_eq!(factor.entropy, Some(160)); // 20 bytes * 8 bits = 160 bits
  }
}
