use rand::{Rng, RngCore, rngs::OsRng};
use serde_json::json;

use crate::{error::MFKDF2Result, setup::factors::MFKDF2Factor};

pub struct HMACSHA1Options {
  pub id:     Option<String>,
  pub secret: Option<[u8; 20]>,
}

pub fn hmacsha1(options: HMACSHA1Options) -> MFKDF2Result<MFKDF2Factor> {
  let secret = options.secret.unwrap_or_else(|| {
    let mut secret = [0u8; 20];
    OsRng.fill_bytes(&mut secret);
    secret
  });

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    kind: "hmacsha1".to_string(),
    id: options.id.unwrap_or("hmacsha1".to_string()),
    data: secret.to_vec(),
    salt,
    params: Some(Box::new(move || {
      let challenge = OsRng.r#gen::<u64>();
      let response = crate::crypto::hmacsha1(&secret, challenge);
      let pad = response.iter().zip(secret.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
      Box::pin(async move { json!({ "challenge": challenge, "pad": pad }) })
    })),
    entropy: Some(160),
    output: Some(Box::new(move || Box::pin(async move { json!({ "secret": secret }) }))),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_hmacsha1_with_known_secret() {
    // Use a known secret for deterministic testing
    let known_secret = [
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14,
    ];

    let factor =
      hmacsha1(HMACSHA1Options { id: Some("test".to_string()), secret: Some(known_secret) })
        .unwrap();

    assert_eq!(factor.kind, "hmacsha1");
    assert_eq!(factor.id, "test");
    assert_eq!(factor.data, known_secret.to_vec());

    // Get the challenge and pad from params
    let params = factor.params.unwrap()().await;
    let challenge = params["challenge"].as_u64().unwrap();
    let pad = params["pad"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_u64().unwrap() as u8)
      .collect::<Vec<u8>>();

    // Compute HMAC-SHA1 response externally to verify
    let expected_response = crate::crypto::hmacsha1(&known_secret, challenge);

    // Verify the pad is correct (response XOR secret)
    let expected_pad: Vec<u8> =
      expected_response.iter().zip(known_secret.iter()).map(|(a, b)| a ^ b).collect();

    assert_eq!(pad, expected_pad);

    // Verify we can recover the response from pad XOR secret
    let recovered_response: Vec<u8> =
      pad.iter().zip(known_secret.iter()).map(|(a, b)| a ^ b).collect();

    assert_eq!(recovered_response, expected_response.to_vec());
  }

  #[tokio::test]
  async fn test_hmacsha1_random_secret() {
    let factor = hmacsha1(HMACSHA1Options { id: None, secret: None }).unwrap();
    assert_eq!(factor.kind, "hmacsha1");
    assert_eq!(factor.id, "hmacsha1");
    assert_eq!(factor.data.len(), 20); // Secret should be 20 bytes
    assert!(factor.params.is_some());
    assert!(factor.output.is_some());
    assert_eq!(factor.entropy, Some(160)); // 20 bytes * 8 bits = 160 bits
  }
}
