use base64::Engine;
use serde_json::{Value, json};

use crate::{
  crypto::decrypt,
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::MFKDF2Result,
  otpauth::generate_hotp_code,
  setup::factors::hotp::{HOTP, HOTPConfig, HOTPParams, mod_positive},
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

      self.target = (params.offset + self.code) % 10_u32.pow(params.digits);
    }

    Ok(())
  }

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    let params: HOTPParams = serde_json::from_value(self.params.clone())?;

    // Decrypt the secret using the factor key
    let pad = base64::prelude::BASE64_STANDARD.decode(&params.pad)?;
    let padded_secret = decrypt(pad, &key.0);

    // Generate HOTP code with incremented counter
    let counter = params.counter + 1;
    let generated_code =
      generate_hotp_code(&padded_secret[..20], counter, &params.hash, params.digits);

    // Calculate new offset
    let new_offset =
      mod_positive(i64::from(self.target) - i64::from(generated_code), 10_i64.pow(params.digits));

    Ok(json!({
      "hash": params.hash.to_string(),
      "digits": params.digits,
      "pad": params.pad,
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
      config: HOTPConfig::default(),
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
  use crate::{
    derive::factors::hotp as derive_hotp,
    otpauth::HashAlgorithm,
    setup::factors::{hotp as setup_hotp, hotp::HOTPOptions},
  };

  #[test]
  fn hotp_round_trip() {
    // Setup phase
    let secret = b"hello world mfkdf2!!".to_vec();
    let hotp_options = HOTPOptions {
      id: Some("hotp".to_string()),
      secret: Some(secret.clone()),
      ..Default::default()
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
    let correct_code =
      generate_hotp_code(&hotp.config.secret[..20], counter, &hotp.config.hash, hotp.config.digits);
    let expected_target = u32::from_be_bytes(factor.data().try_into().unwrap());

    // Verify the relationship: target = (offset + correct_code) % 10^digits
    let modulus = 10_u32.pow(hotp.config.digits);
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
      digits: Some(6),
      hash: Some(HashAlgorithm::Sha1),
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
      matches!(err, Err(crate::error::MFKDF2Error::SerializeError(e)) if e.to_string() == "missing field `hash`")
    );
  }
}
