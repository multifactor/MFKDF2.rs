use std::rc::Rc;

use base64::prelude::*;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{
  crypto::aes256_ecb_decrypt,
  derive::{DeriveFactorFn, factors::MFKDF2DerivedFactor},
  error::MFKDF2Result,
};

fn mod_positive(n: i64, m: i64) -> i64 { ((n % m) + m) % m }

fn generate_hotp_code(secret: &[u8], counter: u64, hash: &str, digits: u8) -> u32 {
  let counter_bytes = counter.to_be_bytes();

  let digest = match hash {
    "sha1" => {
      let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
    "sha256" => {
      let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
    "sha512" => {
      let mut mac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
    _ => panic!("Unsupported hash algorithm"),
  };

  // Dynamic truncation as per RFC 4226
  let offset = (digest[digest.len() - 1] & 0xf) as usize;
  let code = ((digest[offset] & 0x7f) as u32) << 24
    | (digest[offset + 1] as u32) << 16
    | (digest[offset + 2] as u32) << 8
    | (digest[offset + 3] as u32);

  code % (10_u32.pow(digits as u32))
}

pub fn hotp(code: u32) -> MFKDF2Result<DeriveFactorFn> {
  Ok(Rc::new(move |params: Value| {
    let offset = params["offset"].as_u64().unwrap() as u32;
    let digits = params["digits"].as_u64().unwrap() as u8;

    // Calculate target
    let target = mod_positive(offset as i64 + code as i64, 10_i64.pow(digits as u32)) as u32;
    let target_bytes = target.to_be_bytes();

    Box::pin(async move {
      Ok(MFKDF2DerivedFactor {
        kind:   "hotp".to_string(),
        data:   target_bytes.to_vec(),
        params: Some(Box::new(move || {
          let params = params.clone();
          Box::pin(async move {
            // Decrypt the secret using the factor key (placeholder for now)
            let pad_b64 = params["pad"].as_str().unwrap();
            let pad = base64::prelude::BASE64_STANDARD.decode(pad_b64).unwrap();
            let placeholder_key = [0u8; 32]; // This should come from the actual key
            let decrypted = aes256_ecb_decrypt(pad, &placeholder_key);
            let secret_size = params["secretSize"].as_u64().unwrap() as usize;
            let secret = &decrypted[..secret_size];

            // Generate HOTP code with incremented counter
            let counter = params["counter"].as_u64().unwrap() + 1;
            let hash = params["hash"].as_str().unwrap();
            let generated_code = generate_hotp_code(secret, counter, hash, digits);

            // Calculate new offset
            let new_offset =
              mod_positive(target as i64 - generated_code as i64, 10_i64.pow(digits as u32)) as u32;

            json!({
              "hash": hash,
              "digits": digits,
              "pad": pad_b64,
              "secretSize": secret_size,
              "counter": counter,
              "offset": new_offset
            })
          })
        })),
        output: Some(Box::new(move || Box::pin(async move { json!({}) }))),
      })
    })
  }))
}

#[cfg(test)]
mod tests {
  #![allow(clippy::unwrap_used)]
  use super::*;

  #[tokio::test]
  async fn test_hotp_derive() {
    // Create mock parameters that would come from setup
    let params = json!({
      "hash": "sha1",
      "digits": 6,
      "pad": "dGVzdCBwYWQ=", // base64 encoded "test pad"
      "secretSize": 8,
      "counter": 1,
      "offset": 123456
    });

    let derive_fn = hotp(654321).unwrap();
    let result = derive_fn(params).await.unwrap();

    assert_eq!(result.kind, "hotp");
    assert_eq!(result.data.len(), 4); // u32 target as bytes
    assert!(result.params.is_some());
    assert!(result.output.is_some());
  }

  #[test]
  fn test_generate_hotp_code_consistency() {
    let secret = b"test secret";
    let counter = 42;
    let digits = 6;

    // Test different hash algorithms produce different results
    let code_sha1 = generate_hotp_code(secret, counter, "sha1", digits);
    let code_sha256 = generate_hotp_code(secret, counter, "sha256", digits);
    let code_sha512 = generate_hotp_code(secret, counter, "sha512", digits);

    // All should be valid 6-digit codes
    assert!(code_sha1 < 1_000_000);
    assert!(code_sha256 < 1_000_000);
    assert!(code_sha512 < 1_000_000);

    // Different algorithms should typically produce different codes
    // (though theoretically they could be the same by chance)
    println!("SHA1: {}, SHA256: {}, SHA512: {}", code_sha1, code_sha256, code_sha512);
  }
}
