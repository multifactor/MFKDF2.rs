use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
  crypto::encrypt,
  definitions::{Key, MFKDF2Factor},
  error::MFKDF2Result,
  rng,
  setup::factors::{FactorMetadata, FactorSetup, FactorType},
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HmacSha1Options {
  pub id:     Option<String>,
  pub secret: Option<Vec<u8>>,
}

impl Default for HmacSha1Options {
  fn default() -> Self { Self { id: Some("hmacsha1".to_string()), secret: None } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HmacSha1Response(pub [u8; 20]);

impl From<[u8; 20]> for HmacSha1Response {
  fn from(value: [u8; 20]) -> Self { HmacSha1Response(value) }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HmacSha1 {
  pub response:      Option<HmacSha1Response>,
  pub params:        Option<String>,
  pub padded_secret: Vec<u8>,
}

impl FactorMetadata for HmacSha1 {
  fn kind(&self) -> String { "hmacsha1".to_string() }

  fn bytes(&self) -> Vec<u8> { self.padded_secret.clone() }
}

impl FactorSetup for HmacSha1 {
  type Output = Value;
  type Params = Value;

  fn params(&self, _key: Key) -> MFKDF2Result<Value> {
    let mut challenge = [0u8; 64];
    rng::fill_bytes(&mut challenge);

    let response = crate::crypto::hmacsha1(&self.padded_secret[..20], &challenge);
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(&response);
    let pad = encrypt(&self.padded_secret, &padded_key);

    Ok(json!({
      "challenge": hex::encode(challenge),
      "pad": hex::encode(pad),
    }))
  }

  fn output(&self) -> Self::Output {
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
  let id = options.id.clone().unwrap_or("hmacsha1".to_string());

  let secret = if let Some(secret) = options.secret {
    secret
  } else {
    let mut secret = [0u8; 20];
    rng::fill_bytes(&mut secret);
    secret.to_vec()
  };
  if secret.len() != 20 {
    return Err(crate::error::MFKDF2Error::InvalidSecretLength(id));
  }
  let mut secret_pad = [0u8; 12];
  rng::fill_bytes(&mut secret_pad);
  let padded_secret = secret.into_iter().chain(secret_pad).collect();

  Ok(MFKDF2Factor {
    id:          Some(id),
    factor_type: FactorType::HmacSha1(HmacSha1 { padded_secret, response: None, params: None }),
    entropy:     Some(160.0),
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn setup_hmacsha1(options: HmacSha1Options) -> MFKDF2Result<MFKDF2Factor> {
  hmacsha1(options)
}

#[cfg(test)]
mod tests {
  use super::*;

  const SECRET: [u8; 20] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
  ];

  fn mock_construction() -> MFKDF2Factor {
    hmacsha1(HmacSha1Options { id: Some("test".to_string()), secret: Some(SECRET.to_vec()) })
      .unwrap()
  }

  #[test]
  fn known_secret() {
    // Use a known secret for deterministic testing
    let factor = mock_construction();

    assert_eq!(factor.kind(), "hmacsha1");
    assert_eq!(factor.id, Some("test".to_string()));
    assert_eq!(factor.data()[..20], SECRET);

    // Get the challenge and pad from params
    let params = factor.factor_type.setup().params([0u8; 32].into()).unwrap();

    assert!(params.is_object());

    let challenge = hex::decode(params["challenge"].as_str().unwrap()).unwrap();
    let pad = hex::decode(params["pad"].as_str().unwrap()).unwrap();

    // Compute HMAC-SHA1 response externally to verify
    let expected_response = crate::crypto::hmacsha1(&SECRET, &challenge);

    // Verify the pad is correct (ENC(secret, key))
    let mut padded_secret = [0u8; 32];
    padded_secret[..SECRET.len()].copy_from_slice(&SECRET);
    let mut padded_key = [0u8; 32];
    padded_key[..expected_response.len()].copy_from_slice(&expected_response);
    let expected_pad = encrypt(&padded_secret, &padded_key);

    // verify partial pad (multiple of 16) is correct
    assert_eq!(pad[..16], expected_pad[..16]);
  }

  #[test]
  fn random_secret() {
    let factor = hmacsha1(HmacSha1Options { id: None, secret: None }).unwrap();
    assert_eq!(factor.kind(), "hmacsha1");
    assert_eq!(factor.id, Some("hmacsha1".to_string()));
    assert_eq!(factor.data().len(), 32); // Secret should be 20 bytes + 12 bytes of padding
    assert!(factor.factor_type.setup().params([0u8; 32].into()).unwrap().is_object());
    assert!(factor.factor_type.output().is_object());
    assert_eq!(factor.entropy, Some(160.0)); // 20 bytes * 8 bits = 160 bits
  }

  #[test]
  fn invalid_secret() {
    let result = hmacsha1(HmacSha1Options { id: None, secret: Some(vec![0u8; 19]) });
    assert!(matches!(result, Err(crate::error::MFKDF2Error::InvalidSecretLength(_))));
  }

  #[test]
  fn output_setup() {
    let factor = mock_construction();
    let output = factor.factor_type.output();
    assert!(output.is_object());

    let secret = output["secret"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_u64().unwrap() as u8)
      .collect::<Vec<u8>>();

    assert_eq!(secret, factor.data()[..20]);
  }

  #[test]
  fn invalid_id() {
    let result = hmacsha1(HmacSha1Options { id: Some("".to_string()), secret: None });
    assert!(matches!(result, Err(crate::error::MFKDF2Error::MissingFactorId)));
  }
}
