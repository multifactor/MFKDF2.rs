use base64::Engine;
use serde_json::{Value, json};

use crate::{
  crypto::decrypt,
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  otpauth::{HashAlgorithm, generate_hotp_code},
  setup::factors::hotp::{HOTP, HOTPOptions, HOTPParams, mod_positive},
};

impl FactorDerive for HOTP {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    // Store the policy parameters for derive phase
    self.params = params.clone();

    // If this is a derive factor (has a code), calculate target and store in options.secret
    if self.code != 0 {
      let params: HOTPParams = serde_json::from_value(params)?;

      let offset = params.offset;

      let digits = params.digits;
      let modulus = 10_u64.pow(digits as u32);
      let target = (offset as u64 + self.code as u64) % modulus;

      // Store target as 4-byte big-endian (matches JS implementation)
      self.target = target as u32;
    }

    Ok(())
  }

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    // Decrypt the secret using the factor key
    let pad_b64 =
      self.params["pad"].as_str().ok_or(MFKDF2Error::MissingDeriveParams("pad".to_string()))?;
    let pad = base64::prelude::BASE64_STANDARD.decode(pad_b64)?;
    let padded_secret = decrypt(pad, &key.0);

    // Generate HOTP code with incremented counter
    let counter = self.params["counter"]
      .as_u64()
      .ok_or(MFKDF2Error::MissingDeriveParams("counter".to_string()))?
      + 1;
    let hash: HashAlgorithm = serde_json::from_value(self.params["hash"].clone())?;
    let generated_code =
      generate_hotp_code(&padded_secret[..20], counter, &hash, self.options.digits);

    // Calculate new offset
    let new_offset = mod_positive(
      i64::from(self.target) - i64::from(generated_code),
      10_i64.pow(self.options.digits as u32),
    );

    Ok(json!({
      "hash": hash.to_string(),
      "digits": self.options.digits,
      "pad": pad_b64,
      "counter": counter,
      "offset": new_offset
    }))
  }
}

pub fn hotp(code: u32) -> MFKDF2Result<MFKDF2Factor> {
  // Create HOTP factor with the user-provided code
  // The target will be calculated in include_params once we have the policy parameters
  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::HOTP(HOTP {
      options: HOTPOptions::default(),
      params: Value::Null,
      code,
      target: 0,
    }),
    entropy:     None,
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn derive_hotp(code: u32) -> MFKDF2Result<MFKDF2Factor> { hotp(code) }

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{derive::factors::hotp as derive_hotp, setup::factors::hotp as setup_hotp};

  #[test]
  fn hotp_round_trip() {
    // Setup phase
    let secret = b"hello world mfkdf2!!".to_vec();
    let hotp_options = HOTPOptions {
      id:     Some("hotp".to_string()),
      secret: Some(secret.clone()),
      digits: 6,
      hash:   HashAlgorithm::Sha1,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    };

    let factor = setup_hotp(hotp_options).unwrap();
    let hotp = match factor.factor_type {
      FactorType::HOTP(ref h) => h,
      _ => panic!("Wrong factor type"),
    };

    // Simulate the policy creation process
    let mock_key = [42u8; 32]; // Mock factor key
    let setup_params = factor.factor_type.setup().params(mock_key.into()).unwrap();

    // Extract the expected HOTP code that should work
    let counter = setup_params["counter"].as_u64().unwrap();
    let offset = setup_params["offset"].as_u64().unwrap() as u32;

    // Generate the correct HOTP code that the user would need to provide
    let padded_secret = hotp.options.secret.as_ref().unwrap();
    let correct_code =
      generate_hotp_code(&padded_secret[..20], counter, &hotp.options.hash, hotp.options.digits);
    let expected_target = u32::from_be_bytes(factor.data().try_into().unwrap());

    // Verify the relationship: target = (offset + correct_code) % 10^digits
    let modulus = 10_u32.pow(u32::from(hotp.options.digits));
    assert_eq!(expected_target, (offset + correct_code) % modulus);

    // Derive phase - user provides the correct HOTP code
    let mut derive_material = derive_hotp(correct_code).unwrap();
    derive_material.factor_type.include_params(setup_params).unwrap();

    // The derived material should have the same target data as setup
    assert_eq!(factor.data().clone(), derive_material.data());
    assert_eq!(derive_material.kind(), "hotp");
  }

  #[test]
  fn hotp_derive_params_increment() {
    // Test that derive params increment the counter correctly
    let secret = b"hello world mfkdf2!!".to_vec();
    let mock_key = [42u8; 32];

    let hotp_options = HOTPOptions {
      id: Some("hotp".to_string()),
      secret: Some(secret),
      digits: 6,
      hash: HashAlgorithm::Sha1,
      ..Default::default()
    };

    let factor = setup_hotp(hotp_options).unwrap();

    let setup_params = factor.factor_type.setup().params(mock_key.into()).unwrap();

    // Create a derive instance and generate new params
    // NOTE: this is an incorrect code
    let mut derive_factor = derive_hotp(123456).unwrap();
    derive_factor.factor_type.include_params(setup_params.clone()).unwrap();

    let derive_params = derive_factor.factor_type.params(mock_key.into()).unwrap();

    // Counter should be incremented
    let original_counter = setup_params["counter"].as_u64().unwrap();
    let new_counter = derive_params["counter"].as_u64().unwrap();
    assert_eq!(new_counter, original_counter + 1);

    // Other fields should be preserved or updated appropriately
    assert_eq!(setup_params["hash"], derive_params["hash"]);
    assert_eq!(setup_params["digits"], derive_params["digits"]);
    assert_eq!(setup_params["pad"], derive_params["pad"]);
  }

  #[test]
  fn include_params_missing_fields() {
    let mut derive_factor = derive_hotp(123456).unwrap();
    let params = json!({ "digits": 6 });
    let err = derive_factor.factor_type.include_params(params);
    assert!(
      matches!(err, Err(MFKDF2Error::SerializeError(e)) if e.to_string() == "missing field `hash`")
    );
  }
}
