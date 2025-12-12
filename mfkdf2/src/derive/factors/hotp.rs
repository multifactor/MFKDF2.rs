//! This module constructs [`MFKDF2Factor`] witnesses Wᵢⱼ for the derive phase corresponding
//! to the setup factors defined in [hotp](`crate::setup::factors::hotp()`).
//! - During setup, the HOTP factor chooses a secret target code and encodes an offset and encrypted
//!   pad into the policy;
//! - During derive, this module consumes the HOTP code Wᵢⱼ and reconstructs the same target value
//!   using the stored offset so that the factor contributes stable material to the key derivation
//!   while remaining backward‑compatible with existing OATH HOTP applications.
use base64::Engine;

use crate::{
  crypto::decrypt,
  defaults::hotp as hotp_defaults,
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::MFKDF2Result,
  otpauth::generate_otp_token,
  setup::factors::hotp::{HOTP, HOTPOutput, HOTPParams, mod_positive},
};

impl FactorDerive for HOTP {
  /// Includes the public parameters for in factor state and calculates the target value.
  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    // Store the policy parameters for derive phase

    // If this is a derive factor (has a code), calculate target and store in options.secret
    if self.code != 0 {
      self.target = (params.offset + self.code) % 10_u32.pow(params.digits);
    }

    self.params = Some(params);
    Ok(())
  }

  /// Decrypts the secret and generates a new HOTP code with incremented counter.
  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> {
    let params = self
      .params
      .as_ref()
      .ok_or_else(|| crate::error::MFKDF2Error::MissingDeriveParams("params".to_string()))?;

    // Decrypt the secret using the factor key
    let pad = base64::prelude::BASE64_STANDARD.decode(&params.pad)?;
    #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
    let mut padded_secret = decrypt(pad, key);

    // Generate HOTP code with incremented counter
    let counter = params.counter + 1;
    let generated_code =
      generate_otp_token(&padded_secret[..20], counter, &params.hash, params.digits);

    // Calculate new offset
    let new_offset =
      mod_positive(i64::from(self.target) - i64::from(generated_code), 10_i64.pow(params.digits));

    #[cfg(feature = "zeroize")]
    {
      use zeroize::Zeroize;
      padded_secret.zeroize();
    }

    Ok(HOTPParams {
      hash: params.hash.clone(),
      digits: params.digits,
      pad: params.pad.clone(),
      counter,
      offset: new_offset,
    })
  }

  fn output(&self) -> Self::Output {
    HOTPOutput {
      scheme:    "otpauth".to_string(),
      type_:     "hotp".to_string(),
      label:     hotp_defaults::LABEL.to_string(),
      secret:    vec![0u8; 20],
      issuer:    hotp_defaults::ISSUER.to_string(),
      algorithm: hotp_defaults::HASH.to_string(),
      digits:    hotp_defaults::DIGITS,
      counter:   hotp_defaults::COUNTER,
      uri:       String::new(),
    }
  }
}

/// HOTP factor construction derive phase
///
/// The code should be the numeric one‑time password displayed by an authenticator app that has
/// been paired with the HOTP secret configured during setup.
///
/// # Errors
///
/// - [`MFKDF2Error::Serialize`](`crate::error::MFKDF2Error::Serialize`) if the stored policy
///   parameters cannot be decoded into [`HOTPParams`](`crate::setup::factors::hotp::HOTPParams`)
///   (for example, missing or malformed fields)
///
/// # Example
///
/// Single‑factor setup/derive using HOTP within `KeySetup`/`KeyDerive`:
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   otpauth::HashAlgorithm,
/// #   setup::{
/// #     self,
/// #     factors::hotp::{HOTPOptions},
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive,
/// # };
/// let secret = b"hello world mfkdf2!!".to_vec();
/// let options = HOTPOptions {
///   id: Some("hotp".to_string()),
///   secret: Some(secret),
///   digits: Some(6),
///   hash: Some(HashAlgorithm::Sha1),
///   ..Default::default()
/// };
///
/// let setup_factor = setup::factors::hotp(options)?;
/// let hotp = if let mfkdf2::definitions::FactorType::HOTP(ref h) = setup_factor.factor_type {
///   h.clone()
/// } else {
///   unreachable!()
/// };
/// let setup_key = setup::key(&[setup_factor], MFKDF2Options::default())?;
///
/// let policy_factor = setup_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
/// let counter = match &policy_factor.params {
///   mfkdf2::definitions::factor::FactorParams::HOTP(p) => p.counter,
///   _ => unreachable!(),
/// };
/// let code =
///   mfkdf2::otpauth::generate_otp_token(&hotp.secret[..20], counter, &hotp.hash, hotp.digits);
///
/// let derive_factor = derive::factors::hotp(code)?;
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("hotp".to_string(), derive_factor)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn hotp(code: u32) -> MFKDF2Result<MFKDF2Factor> {
  // Create HOTP factor with the user-provided code
  // The target will be calculated in include_params once we have the policy parameters
  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::HOTP(HOTP {
      id: hotp_defaults::ID.to_string(),
      secret: vec![0u8; 32], // Placeholder, will be decrypted from params
      digits: hotp_defaults::DIGITS,
      hash: hotp_defaults::HASH,
      issuer: hotp_defaults::ISSUER.to_string(),
      label: hotp_defaults::LABEL.to_string(),
      params: Some(HOTPParams::default()),
      code,
      target: 0,
    }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_hotp(code: u32) -> MFKDF2Result<MFKDF2Factor> { hotp(code) }

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
    let setup_params = match factor.factor_type.setup().params(mock_key.into()).unwrap() {
      crate::definitions::factor::FactorParams::HOTP(p) => p,
      _ => panic!("Expected HOTP params"),
    };
    let counter = setup_params.counter;
    let offset = setup_params.offset;

    // Generate the correct HOTP code that the user would need to provide
    let correct_code = generate_otp_token(&hotp.secret[..20], counter, &hotp.hash, hotp.digits);
    let expected_target = u32::from_be_bytes(factor.data().try_into().unwrap());

    // Verify the relationship: target = (offset + correct_code) % 10^digits
    let modulus = 10_u32.pow(hotp.digits);
    assert_eq!(expected_target, (offset + correct_code) % modulus);

    // Derive phase - user provides the correct HOTP code
    let mut derive_material = derive_hotp(correct_code).unwrap();
    derive_material
      .factor_type
      .include_params(crate::definitions::factor::FactorParams::HOTP(setup_params))
      .unwrap();

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

    let setup_params = match factor.factor_type.setup().params(mock_key.into()).unwrap() {
      crate::definitions::factor::FactorParams::HOTP(p) => p,
      _ => panic!("Expected HOTP params"),
    };

    // Create a derive instance and generate new params
    // NOTE: this is an incorrect code
    let mut derive_factor = derive_hotp(123456).unwrap();
    derive_factor
      .factor_type
      .include_params(crate::definitions::factor::FactorParams::HOTP(setup_params.clone()))
      .unwrap();

    let derive_params = match derive_factor.factor_type.derive().params(mock_key.into()).unwrap() {
      crate::definitions::factor::FactorParams::HOTP(p) => p,
      _ => panic!("Expected HOTP params"),
    };

    // Counter should be incremented
    assert_eq!(derive_params.counter, setup_params.counter + 1);

    // Other fields should be preserved or updated appropriately
    assert_eq!(derive_params.hash, setup_params.hash);
    assert_eq!(derive_params.digits, setup_params.digits);
    assert_eq!(derive_params.pad, setup_params.pad);
  }

  #[test]
  fn include_params_missing_fields() {
    use serde_json::json;
    // Try to deserialize invalid params
    let params_result: Result<HOTPParams, _> = serde_json::from_value(json!({ "digits": 6 }));
    assert!(params_result.is_err());
  }
}
