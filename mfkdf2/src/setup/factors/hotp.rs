use base64::prelude::*;
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{
  crypto::{decrypt, encrypt},
  error::MFKDF2Result,
  setup::factors::{FactorTrait, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct HOTPOptions {
  pub id:     Option<String>,
  pub secret: Option<Vec<u8>>,
  pub digits: u8,
  pub hash:   OTPHash,
  pub issuer: String,
  pub label:  String,
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Enum)]
pub enum OTPHash {
  Sha1,
  Sha256,
  Sha512,
}

impl Default for HOTPOptions {
  fn default() -> Self {
    Self {
      id:     Some("hotp".to_string()),
      secret: None,
      digits: 6,
      hash:   OTPHash::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "mfkdf.com".to_string(),
    }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct HOTP {
  // TODO (sambhav): is it safe to add options in the factor struct here?
  pub options: HOTPOptions,
  pub params:  String,
  pub code:    u32,
  pub target:  u32,
}

impl FactorTrait for HOTP {
  fn kind(&self) -> String { "hotp".to_string() }

  fn bytes(&self) -> Vec<u8> {
    // For setup factors, return the secret or empty vec
    self.target.to_be_bytes().to_vec()
  }

  fn params_setup(&self, key: [u8; 32]) -> Value {
    // Generate or use provided secret
    let padded_secret = if let Some(secret) = self.options.secret.clone() {
      secret
    } else {
      let mut secret = vec![0u8; 32]; // Default to 32 bytes like JS
      OsRng.fill_bytes(&mut secret);
      secret
    };

    // Generate HOTP code with counter = 1
    let code = generate_hotp_code(&padded_secret[..20], 1, &self.options.hash, self.options.digits);

    // Calculate offset
    let offset =
      mod_positive(self.target as i64 - code as i64, 10_i64.pow(self.options.digits as u32)) as u32;

    let pad = encrypt(&padded_secret, &key);

    json!({
      "hash": match self.options.hash {
        OTPHash::Sha1 => "sha1",
        OTPHash::Sha256 => "sha256",
        OTPHash::Sha512 => "sha512"
      },
      "digits": self.options.digits,
      "pad": base64::prelude::BASE64_STANDARD.encode(&pad),
      "counter": 1,
      "offset": offset
    })
  }

  fn output_setup(&self, _key: [u8; 32]) -> Value {
    json!({
      "scheme": "otpauth",
      "type": "hotp",
      "label": self.options.label,
      "secret": base64::prelude::BASE64_STANDARD.encode(&self.options.secret.clone().unwrap()[..20]),
      "issuer": self.options.issuer,
      "algorithm": match self.options.hash {
        OTPHash::Sha1 => "sha1",
        OTPHash::Sha256 => "sha256",
        OTPHash::Sha512 => "sha512"
      },
      "digits": self.options.digits,
      "counter": 1,
      // TODO (sambhav): either generate uri yourself or use an external lib
      "uri": ""
    })
  }

  fn params_derive(&self, key: [u8; 32]) -> Value {
    // Decrypt the secret using the factor key
    let params: Value = serde_json::from_str(&self.params).unwrap();
    let pad_b64 = params["pad"].as_str().unwrap();
    let pad = base64::prelude::BASE64_STANDARD.decode(pad_b64).unwrap();
    let decrypted = decrypt(pad, &key);
    let secret_size = params["secretSize"].as_u64().unwrap() as usize;
    let secret = &decrypted[..secret_size];

    // Generate HOTP code with incremented counter
    let counter = params["counter"].as_u64().unwrap() + 1;
    let hash = params["hash"].as_str().unwrap();
    let hash = match hash {
      "sha1" => OTPHash::Sha1,
      "sha256" => OTPHash::Sha256,
      "sha512" => OTPHash::Sha512,
      _ => panic!("Unsupported hash algorithm"),
    };
    let generated_code = generate_hotp_code(secret, counter, &hash, self.options.digits);

    // Calculate new offset
    let new_offset = mod_positive(
      self.target as i64 - generated_code as i64,
      10_i64.pow(self.options.digits as u32),
    ) as u32;

    json!({
      "hash": hash,
      "digits": self.options.digits,
      "pad": pad_b64,
      "secretSize": secret_size,
      "counter": counter,
      "offset": new_offset
    })
  }

  fn output_derive(&self, _key: [u8; 32]) -> Value { json!({}) }

  fn include_params(&mut self, params: Value) {
    // Store the policy parameters for derive phase
    dbg!(&params);
    self.params = serde_json::to_string(&params).unwrap();

    // If this is a derive factor (has a code), calculate target and store in options.secret
    if self.code != 0
      && let (Some(offset), Some(digits)) = (params["offset"].as_u64(), params["digits"].as_u64())
    {
      let modulus = 10_u64.pow(digits as u32);
      let target = (offset + self.code as u64) % modulus;

      // Store target as 4-byte big-endian (matches JS implementation)
      self.target = target as u32;
    }
  }
}

fn mod_positive(n: i64, m: i64) -> i64 { ((n % m) + m) % m }

pub fn generate_hotp_code(secret: &[u8], counter: u64, hash: &OTPHash, digits: u8) -> u32 {
  let counter_bytes = counter.to_be_bytes();

  let digest = match hash {
    OTPHash::Sha1 => {
      let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
    OTPHash::Sha256 => {
      let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
    OTPHash::Sha512 => {
      let mut mac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
  };

  // Dynamic truncation as per RFC 4226
  let offset = (digest[digest.len() - 1] & 0xf) as usize;
  let code = ((digest[offset] & 0x7f) as u32) << 24
    | (digest[offset + 1] as u32) << 16
    | (digest[offset + 2] as u32) << 8
    | (digest[offset + 3] as u32);

  code % (10_u32.pow(digits as u32))
}

pub fn hotp(options: HOTPOptions) -> MFKDF2Result<MFKDF2Factor> {
  let mut options = options;

  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  if options.digits < 6 || options.digits > 8 {
    return Err(crate::error::MFKDF2Error::InvalidHOTPDigits);
  }

  let secret = options.secret.unwrap_or_else(|| {
    let mut secret = vec![0u8; 20];
    OsRng.fill_bytes(&mut secret);
    secret
  });
  let mut secret_pad = [0u8; 12];
  OsRng.fill_bytes(&mut secret_pad);
  let padded_secret = secret.iter().chain(secret_pad.iter()).cloned().collect();
  options.secret = Some(padded_secret);

  // Generate random target
  let target = OsRng.gen_range(0..10_u32.pow(u32::from(options.digits)));

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  let entropy = Some((options.digits as f64 * 10.0_f64.log2()) as u32);

  // TODO (autoparallel): Code should possibly be an option, though this follows the same pattern as
  // the password factor which stores the actual password in the struct.
  Ok(MFKDF2Factor {
    id: Some(options.id.clone().unwrap_or("hotp".to_string())),
    factor_type: FactorType::HOTP(HOTP {
      options,
      params: serde_json::to_string(&Value::Null).unwrap(),
      code: 0,
      target,
    }),
    salt: salt.to_vec(),
    entropy,
  })
}

#[uniffi::export]
pub fn setup_hotp(options: HOTPOptions) -> MFKDF2Result<MFKDF2Factor> { hotp(options) }

#[cfg(test)]
mod tests {
  // #![allow(clippy::unwrap_used)]
  // use super::*;

  // #[tokio::test]
  // async fn test_hotp_setup_with_known_secret() {
  //   let key = [0u8; 32];
  //   let options = HOTPOptions {
  //     id:     Some("test_hotp".to_string()),
  //     secret: Some(b"hello world".to_vec()),
  //     digits: 6,
  //     hash:   OTPHash::Sha1,
  //     issuer: "MFKDF".to_string(),
  //     label:  "test".to_string(),
  //   };

  //   let factor = hotp(options).unwrap();
  //   assert_eq!(factor.kind(), "hotp");
  //   assert_eq!(factor.id, Some("test_hotp".to_string()));
  //   assert_eq!(factor.factor_type.bytes().len(), 4); // u32 target as bytes

  //   // Test that params can be generated
  //   let params = factor.factor_type.params_setup(key);
  //   assert!(params["hash"].is_string());
  //   assert!(params["digits"].is_number());
  //   assert!(params["pad"].is_string());
  //   assert!(params["secretSize"].is_number());
  //   assert!(params["counter"].is_number());
  //   assert!(params["offset"].is_number());
  // }

  // #[tokio::test]
  // async fn test_hotp_setup_default_options() {
  //   let key = [0u8; 32];
  //   let options = HOTPOptions::default();
  //   let factor = hotp(options).unwrap();

  //   assert_eq!(factor.kind(), "hotp");
  //   assert_eq!(factor.id, Some("hotp".to_string()));
  //   assert_eq!(factor.factor_type.bytes().len(), 4);
  //   assert!(factor.entropy.is_some());
  //   assert!(factor.factor_type.params_setup(key).is_object());
  //   assert!(factor.factor_type.output_setup(key).is_object());
  // }

  // #[test]
  // fn test_generate_hotp_code() {
  //   let secret = b"hello world";
  //   let counter = 1;
  //   let hash = OTPHash::Sha1;
  //   let digits = 6;

  //   let code = generate_hotp_code(secret, counter, &hash, digits);
  //   assert!(code < 10_u32.pow(digits as u32));

  //   // Same inputs should produce same output
  //   let code2 = generate_hotp_code(secret, counter, &hash, digits);
  //   assert_eq!(code, code2);

  //   // Different counter should produce different output
  //   let code3 = generate_hotp_code(secret, counter + 1, &hash, digits);
  //   assert_ne!(code, code3);
  // }

  // #[test]
  // fn test_hotp_validation() {
  //   // Test invalid digits
  //   let options = HOTPOptions {
  //     digits: 5, // Too small
  //     ..Default::default()
  //   };
  //   assert!(hotp(options).is_err());

  //   let options = HOTPOptions {
  //     digits: 9, // Too large
  //     ..Default::default()
  //   };
  //   assert!(hotp(options).is_err());

  //   // Test empty id
  //   let options = HOTPOptions { id: Some("".to_string()), ..Default::default() };
  //   assert!(hotp(options).is_err());
  // }
}

//   #[test]
//   fn test_hotp_setup() {
//     let options = HOTPOptions {
//       id:     Some("hotp".to_string()),
//       secret: Some(b"hello world".to_vec()),
//       digits: 6,
//       hash:   HOTPHash::Sha1,
//       issuer: "MFKDF".to_string(),
//       label:  "test".to_string(),
//     };

//     let material = HOTP::setup(options).unwrap();
//     assert_eq!(material.kind, "hotp");
//     assert_eq!(material.id, Some("hotp".to_string()));
//     assert_eq!(material.data.len(), 4); // u32 target
//   }

//   #[test]
//   fn test_hotp_round_trip() {
//     // Setup phase
//     let secret = b"hello world".to_vec();
//     let hotp_options = HOTPOptions {
//       id:     Some("hotp".to_string()),
//       secret: Some(secret.clone()),
//       digits: 6,
//       hash:   HOTPHash::Sha1,
//       issuer: "MFKDF".to_string(),
//       label:  "test".to_string(),
//     };

//     let hotp = HOTP::new(hotp_options).unwrap();
//     let setup_material = HOTP::setup(hotp.options.clone()).unwrap();

//     // Simulate the policy creation process
//     let mock_key = [42u8; 32]; // Mock factor key
//     let setup_params = hotp.generate_setup_params(&mock_key).unwrap();

//     // Extract the expected HOTP code that should work
//     let counter = setup_params["counter"].as_u64().unwrap();
//     let offset = setup_params["offset"].as_u64().unwrap() as u32;

//     // Generate the correct HOTP code that the user would need to provide
//     let correct_code =
//       HOTP::generate_hotp_code(&secret, counter, &hotp.options.hash, hotp.options.digits);
//     dbg!(&correct_code);
//     let expected_target = u32::from_be_bytes(setup_material.data.clone().try_into().unwrap());

//     // Verify the relationship: target = (offset + correct_code) % 10^digits
//     let modulus = 10_u32.pow(u32::from(hotp.options.digits));
//     assert_eq!(expected_target, (offset + correct_code) % modulus);

//     // Derive phase - user provides the correct HOTP code
//     let derive_material = HOTPDerive::derive((correct_code, setup_params.clone())).unwrap();

//     // The derived material should have the same target data as setup
//     assert_eq!(setup_material.data.clone(), derive_material.data);
//     assert_eq!(derive_material.kind, "hotp");

//     println!("✅ HOTP Round-trip test passed!");
//     println!("   Target: {}", expected_target);
//     println!("   Correct HOTP code: {}", correct_code);
//     println!("   Offset: {}", offset);
//   }

//   #[test]
//   fn test_hotp_derive_params_increment() {
//     // Test that derive params increment the counter correctly
//     let secret = b"hello world".to_vec();
//     let mock_key = [42u8; 32];

//     let hotp_options = HOTPOptions {
//       id: Some("hotp".to_string()),
//       secret: Some(secret),
//       digits: 6,
//       hash: HOTPHash::Sha1,
//       ..Default::default()
//     };

//     let hotp = HOTP::new(hotp_options).unwrap();
//     let setup_params = hotp.generate_setup_params(&mock_key).unwrap();

//     // Create a derive instance and generate new params
//     let derive_instance = HOTPDerive::new(123_456, setup_params.clone());
//     let derive_params = derive_instance.generate_derive_params(&mock_key).unwrap();

//     // Counter should be incremented
//     let original_counter = setup_params["counter"].as_u64().unwrap();
//     let new_counter = derive_params["counter"].as_u64().unwrap();
//     assert_eq!(new_counter, original_counter + 1);

//     // Other fields should be preserved or updated appropriately
//     assert_eq!(setup_params["hash"], derive_params["hash"]);
//     assert_eq!(setup_params["digits"], derive_params["digits"]);
//     assert_eq!(setup_params["pad"], derive_params["pad"]);
//     assert_eq!(setup_params["secretSize"], derive_params["secretSize"]);
//   }
// }
