use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{
  crypto::{aes256_ecb_decrypt, aes256_ecb_encrypt},
  error::{MFKDF2Error, MFKDF2Result},
  factors::{Derive, Material, Setup},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HOTPOptions {
  pub id:     Option<String>,
  pub secret: Option<Vec<u8>>,
  pub digits: u8,
  pub hash:   HOTPHash,
  pub issuer: String,
  pub label:  String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HOTPHash {
  Sha1,
  Sha256,
  Sha512,
}

impl Default for HOTPOptions {
  fn default() -> Self {
    Self {
      id:     None,
      secret: None,
      digits: 6,
      hash:   HOTPHash::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "mfkdf.com".to_string(),
    }
  }
}

pub struct HOTP {
  target:  u32,
  options: HOTPOptions,
  entropy: u32,
}

impl HOTP {
  // TODO: Just put into setup.
  /// Create a new HOTP factor with the given options
  ///
  /// # Errors
  /// Returns an error if the number of digits is not between 6 and 8
  #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
  pub fn new(options: HOTPOptions) -> MFKDF2Result<Self> {
    // Validate options
    if options.digits < 6 || options.digits > 8 {
      return Err(MFKDF2Error::InvalidHOTPDigits);
    }

    // Generate random target
    let target = OsRng.next_u32() % (10_u32.pow(u32::from(options.digits)));
    let entropy = u32::from(options.digits) * 3; // Approximate log2(10^digits)

    Ok(Self { target, options, entropy })
  }

  /// Generate HOTP code using the standard algorithm
  #[allow(clippy::unwrap_used)]
  fn generate_hotp_code(secret: &[u8], counter: u64, hash: &HOTPHash, digits: u8) -> u32 {
    let counter_bytes = counter.to_be_bytes();

    let digest = match hash {
      HOTPHash::Sha1 => {
        let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
        mac.update(&counter_bytes);
        mac.finalize().into_bytes().to_vec()
      },
      HOTPHash::Sha256 => {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(&counter_bytes);
        mac.finalize().into_bytes().to_vec()
      },
      HOTPHash::Sha512 => {
        let mut mac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
        mac.update(&counter_bytes);
        mac.finalize().into_bytes().to_vec()
      },
    };

    // Dynamic truncation
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let code = u32::from_be_bytes([
      digest[offset] & 0x7f,
      digest[offset + 1],
      digest[offset + 2],
      digest[offset + 3],
    ]);

    code % (10_u32.pow(u32::from(digits)))
  }

  /// Positive modulo operation (handles negative numbers correctly)
  #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
  const fn positive_mod(a: i64, b: u32) -> u32 { ((a % b as i64) + b as i64) as u32 % b }

  /// Generate setup parameters for policy storage
  ///
  /// # Errors
  /// Returns an error if base64 encoding fails
  #[allow(clippy::cast_lossless)]
  pub fn generate_setup_params(&self, key: &[u8; 32]) -> MFKDF2Result<Value> {
    // Use provided secret or generate one based on key size
    let secret = self.options.secret.clone().unwrap_or_else(|| key.to_vec());

    // Generate HOTP code with counter = 1
    let code = Self::generate_hotp_code(&secret, 1, &self.options.hash, self.options.digits);

    // Calculate offset: target - code (mod 10^digits)
    let modulus = 10_u32.pow(u32::from(self.options.digits));
    let offset = Self::positive_mod(self.target as i64 - code as i64, modulus);

    // Encrypt secret with AES-256-ECB using the key
    let mut padded_secret = secret.clone();
    let padding_needed = 16 - (padded_secret.len() % 16);
    if padding_needed != 16 {
      let mut padding = vec![0u8; padding_needed];
      OsRng.fill_bytes(&mut padding);
      padded_secret.extend(padding);
    }
    let encrypted_secret = aes256_ecb_encrypt(&padded_secret, key);

    Ok(json!({
      "hash": match self.options.hash {
        HOTPHash::Sha1 => "sha1",
        HOTPHash::Sha256 => "sha256",
        HOTPHash::Sha512 => "sha512",
      },
      "digits": self.options.digits,
      "pad": general_purpose::STANDARD.encode(&encrypted_secret),
      "secretSize": secret.len(),
      "counter": 1,
      "offset": offset
    }))
  }
}

impl Setup for HOTP {
  type Input = HOTPOptions;
  type Output = MFKDF2Result<Material>;

  fn setup(options: Self::Input) -> Self::Output {
    let hotp = Self::new(options)?;

    Ok(Material {
      id:      hotp.options.id.clone(),
      kind:    "hotp".to_string(),
      data:    hotp.target.to_be_bytes().to_vec(),
      output:  json!({
        "scheme": "otpauth",
        "type": "hotp",
        "label": hotp.options.label,
        "issuer": hotp.options.issuer,
        "algorithm": match hotp.options.hash {
          HOTPHash::Sha1 => "sha1",
          HOTPHash::Sha256 => "sha256",
          HOTPHash::Sha512 => "sha512",
        },
        "digits": hotp.options.digits,
        "counter": 1
      }),
      entropy: hotp.entropy,
    })
  }
}

pub struct HOTPDerive {
  pub code:          u32,
  pub stored_params: Value,
}

impl HOTPDerive {
  pub const fn new(code: u32, stored_params: Value) -> Self { Self { code, stored_params } }

  /// Generate derive parameters (increments counter, recalculates offset)
  ///
  /// # Errors
  /// Returns an error if base64 decoding fails
  #[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
  pub fn generate_derive_params(&self, key: &[u8; 32]) -> MFKDF2Result<Value> {
    // Extract stored parameters
    let hash_str = self.stored_params["hash"].as_str().unwrap_or("sha1");
    let hash = match hash_str {
      "sha256" => HOTPHash::Sha256,
      "sha512" => HOTPHash::Sha512,
      _ => HOTPHash::Sha1,
    };
    let digits = self.stored_params["digits"].as_u64().unwrap_or(6) as u8;
    let secret_size = self.stored_params["secretSize"].as_u64().unwrap_or(32) as usize;
    let current_counter = self.stored_params["counter"].as_u64().unwrap_or(1);
    let current_offset = self.stored_params["offset"].as_u64().unwrap_or(0) as u32;

    // Decrypt the secret from stored params
    let pad_b64 = self.stored_params["pad"].as_str().unwrap_or("");
    let encrypted_secret = general_purpose::STANDARD.decode(pad_b64)?;
    let decrypted_padded = aes256_ecb_decrypt(encrypted_secret, key);
    let secret = &decrypted_padded[..secret_size];

    // Calculate new target from user's code and stored offset
    let modulus = 10_u32.pow(u32::from(digits));
    let target = HOTP::positive_mod(current_offset as i64 + self.code as i64, modulus);

    // Generate new HOTP code with incremented counter
    let new_counter = current_counter + 1;
    let new_code = HOTP::generate_hotp_code(secret, new_counter, &hash, digits);

    // Calculate new offset
    let new_offset = HOTP::positive_mod(target as i64 - new_code as i64, modulus);

    Ok(json!({
      "hash": hash_str,
      "digits": digits,
      "pad": pad_b64, // Keep same encrypted secret
      "secretSize": secret_size,
      "counter": new_counter,
      "offset": new_offset
    }))
  }
}

impl Derive for HOTPDerive {
  type Input = (u32, Value);
  // (code, stored_params)
  type Output = MFKDF2Result<Material>;

  #[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
  fn derive((code, stored_params): Self::Input) -> Self::Output {
    let derive_instance = Self::new(code, stored_params);

    // Calculate target from code and offset
    let current_offset = derive_instance.stored_params["offset"].as_u64().unwrap_or(0) as u32;
    let digits = derive_instance.stored_params["digits"].as_u64().unwrap_or(6) as u8;
    let modulus = 10_u32.pow(u32::from(digits));
    let target = HOTP::positive_mod(i64::from(current_offset) + i64::from(code), modulus);

    Ok(Material {
      id:      None,
      kind:    "hotp".to_string(),
      data:    target.to_be_bytes().to_vec(),
      output:  json!({}),
      entropy: u32::from(digits) * 3, // Approximate log2(10^digits)
    })
  }
}

#[cfg(test)]
mod tests {
  #![allow(clippy::unwrap_used)]
  use super::*;

  #[test]
  fn test_hotp_setup() {
    let options = HOTPOptions {
      id:     Some("hotp".to_string()),
      secret: Some(b"hello world".to_vec()),
      digits: 6,
      hash:   HOTPHash::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    };

    let material = HOTP::setup(options).unwrap();
    assert_eq!(material.kind, "hotp");
    assert_eq!(material.id, Some("hotp".to_string()));
    assert_eq!(material.data.len(), 4); // u32 target
  }

  #[test]
  fn test_hotp_round_trip() {
    // Setup phase
    let secret = b"hello world".to_vec();
    let hotp_options = HOTPOptions {
      id:     Some("hotp".to_string()),
      secret: Some(secret.clone()),
      digits: 6,
      hash:   HOTPHash::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    };

    let hotp = HOTP::new(hotp_options).unwrap();
    let setup_material = HOTP::setup(hotp.options.clone()).unwrap();

    // Simulate the policy creation process
    let mock_key = [42u8; 32]; // Mock factor key
    let setup_params = hotp.generate_setup_params(&mock_key).unwrap();

    // Extract the expected HOTP code that should work
    let counter = setup_params["counter"].as_u64().unwrap();
    let offset = setup_params["offset"].as_u64().unwrap() as u32;

    // Generate the correct HOTP code that the user would need to provide
    let correct_code =
      HOTP::generate_hotp_code(&secret, counter, &hotp.options.hash, hotp.options.digits);
    dbg!(&correct_code);
    let expected_target = u32::from_be_bytes(setup_material.data.clone().try_into().unwrap());

    // Verify the relationship: target = (offset + correct_code) % 10^digits
    let modulus = 10_u32.pow(u32::from(hotp.options.digits));
    assert_eq!(expected_target, (offset + correct_code) % modulus);

    // Derive phase - user provides the correct HOTP code
    let derive_material = HOTPDerive::derive((correct_code, setup_params.clone())).unwrap();

    // The derived material should have the same target data as setup
    assert_eq!(setup_material.data.clone(), derive_material.data);
    assert_eq!(derive_material.kind, "hotp");

    println!("✅ HOTP Round-trip test passed!");
    println!("   Target: {}", expected_target);
    println!("   Correct HOTP code: {}", correct_code);
    println!("   Offset: {}", offset);
  }

  #[test]
  fn test_hotp_derive_params_increment() {
    // Test that derive params increment the counter correctly
    let secret = b"hello world".to_vec();
    let mock_key = [42u8; 32];

    let hotp_options = HOTPOptions {
      id: Some("hotp".to_string()),
      secret: Some(secret),
      digits: 6,
      hash: HOTPHash::Sha1,
      ..Default::default()
    };

    let hotp = HOTP::new(hotp_options).unwrap();
    let setup_params = hotp.generate_setup_params(&mock_key).unwrap();

    // Create a derive instance and generate new params
    let derive_instance = HOTPDerive::new(123_456, setup_params.clone());
    let derive_params = derive_instance.generate_derive_params(&mock_key).unwrap();

    // Counter should be incremented
    let original_counter = setup_params["counter"].as_u64().unwrap();
    let new_counter = derive_params["counter"].as_u64().unwrap();
    assert_eq!(new_counter, original_counter + 1);

    // Other fields should be preserved or updated appropriately
    assert_eq!(setup_params["hash"], derive_params["hash"]);
    assert_eq!(setup_params["digits"], derive_params["digits"]);
    assert_eq!(setup_params["pad"], derive_params["pad"]);
    assert_eq!(setup_params["secretSize"], derive_params["secretSize"]);
  }
}
