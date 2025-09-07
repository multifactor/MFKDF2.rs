use std::rc::Rc;

use base64::prelude::*;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{
  crypto::aes256_ecb_decrypt,
  error::MFKDF2Result,
  setup::factors::{
    FactorType, MFKDF2Factor,
    hotp::{HOTP, HOTPOptions},
  },
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

pub fn hotp(code: u32) -> MFKDF2Result<MFKDF2Factor> {
  // Create HOTP factor with the user-provided code
  // The target will be calculated in include_params once we have the policy parameters
  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::HOTP(HOTP {
      options: HOTPOptions::default(),
      params: Value::Null, // Will be set by include_params
      code,
      target: 0,
    }),
    salt:        [0u8; 32],
    entropy:     Some((6 as f64 * 10.0_f64.log2()) as u32),
  })
}
