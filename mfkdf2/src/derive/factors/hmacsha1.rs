//! Factor construction derive phase for the HMAC‑SHA1 factor from
//! [`HMAC-SHA1`](`crate::setup::factors::hmacsha1()`).
//!
//! - During setup, the factor stores a padded HMAC key and a challenge in the policy.
//! - During derive, this module consumes an HMAC response over that challenge and reconstructs the
//!   same padded secret so that the factor contributes identical bytes to the MFKDF2 key
//!   derivation.

use crate::{
  crypto::{decrypt, encrypt},
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::MFKDF2Result,
  setup::factors::hmacsha1::{HmacSha1, HmacSha1Output, HmacSha1Params, HmacSha1Response},
};

impl FactorDerive for HmacSha1 {
  type Output = HmacSha1Output;
  type Params = HmacSha1Params;

  /// Includes the public parameters for in factor state and decrypts the secret material.
  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    if params.pad.is_empty() {
      return Err(crate::error::MFKDF2Error::InvalidDeriveParams("pad".to_string()));
    }

    let response = self.response.as_ref().unwrap();
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(response);

    let pad = hex::decode(&params.pad)
      .map_err(|e| crate::error::MFKDF2Error::InvalidDeriveParams(e.to_string()))?;

    let padded_secret = decrypt(pad, &padded_key);
    self.padded_secret = padded_secret;

    Ok(())
  }

  /// Computes a new challenge and encrypts the secret material as pad for the factor.
  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> {
    let mut challenge = [0u8; 64];
    crate::rng::fill_bytes(&mut challenge);

    let response = crate::crypto::hmacsha1(&self.padded_secret[..20], &challenge);
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(&response);
    let pad = encrypt(&self.padded_secret, &padded_key);

    Ok(HmacSha1Params { challenge: hex::encode(challenge), pad: hex::encode(pad) })
  }

  fn output(&self) -> Self::Output { HmacSha1Output { secret: self.padded_secret.clone() } }
}

/// Factor construction derive phase for an HMAC‑SHA1 factor
///
/// The caller is expected to compute `response = HMAC-SHA1(secret, challenge)` using the secret
/// key material stored by the application and the `challenge` value provided in the setup policy
/// parameters. This helper wraps the response in an [`MFKDF2Factor`] witness Wᵢⱼ that, once
/// combined with the policy, recovers the same padded secret as in setup.
///
/// # Errors
///
/// - [`MFKDF2Error::MissingDeriveParams`](`crate::error::MFKDF2Error::MissingDeriveParams`) if the
///   setup policy omits the `"pad"` parameter when `include_params` is invoked
/// - [`MFKDF2Error::InvalidDeriveParams`](`crate::error::MFKDF2Error::InvalidDeriveParams`) if the
///   `"pad"` field is not valid hex or has an unexpected shape
///
/// # Example
///
/// Single‑factor setup and factor construction derive phase using the HMAC‑SHA1 factor within
/// `KeySetup`/`KeyDerive`:
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   setup::{
/// #     self,
/// #     factors::hmacsha1::{HmacSha1Options},
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive,
/// # };
/// # use hmac::{Mac, Hmac};
/// # use sha1::Sha1;
/// # const HMACSHA1_SECRET: [u8; 20] = [0x11; 20];
/// // KeySetup: build a policy with a single HMAC‑SHA1 factor
/// let setup_factor = setup::factors::hmacsha1(HmacSha1Options {
///   secret: Some(HMACSHA1_SECRET.to_vec()),
///   ..Default::default()
/// })?;
/// let setup_key = setup::key(&[setup_factor], MFKDF2Options::default())?;
///
/// // Read the challenge for this factor from the policy
/// let policy_factor = setup_key.policy.factors.iter().find(|f| f.id == "hmacsha1").unwrap();
/// let setup_params = &policy_factor.params;
/// let challenge = match setup_params {
///   mfkdf2::definitions::factor::FactorParams::HmacSha1(p) => hex::decode(&p.challenge).unwrap(),
///   _ => unreachable!(),
/// };
///
/// // The hardware token (or equivalent) computes HMAC-SHA1 over the challenge
/// let response: [u8; 20] = <Hmac<Sha1> as Mac>::new_from_slice(&HMACSHA1_SECRET)
///   .unwrap()
///   .chain_update(&challenge)
///   .finalize()
///   .into_bytes()
///   .into();
///
/// // Build the derive‑time HMAC witness and run KeyDerive
/// let derive_factor = derive::factors::hmacsha1(response)?;
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("hmacsha1".to_string(), derive_factor)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn hmacsha1(response: impl Into<HmacSha1Response>) -> MFKDF2Result<MFKDF2Factor> {
  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::HmacSha1(HmacSha1 {
      response:      Some(response.into()),
      padded_secret: [0u8; 32].to_vec(),
    }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_hmacsha1(response: HmacSha1Response) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::hmacsha1(response)
}

#[cfg(test)]
mod tests {

  use super::*;
  use crate::{
    crypto::decrypt,
    definitions::FactorType,
    error::MFKDF2Error,
    setup::factors::hmacsha1::{HmacSha1, HmacSha1Options},
  };

  fn mock_hmac_setup() -> MFKDF2Factor {
    let options = HmacSha1Options { id: Some("test".to_string()), secret: Some(vec![0; 20]) };
    crate::setup::factors::hmacsha1::hmacsha1(options).unwrap()
  }

  fn mock_hmac_derive(setup_factor: &MFKDF2Factor, setup_params: &HmacSha1Params) -> FactorType {
    let challenge = hex::decode(&setup_params.challenge).unwrap();
    let output = setup_factor.factor_type.setup().output();
    let secret = match output {
      crate::definitions::factor::FactorOutput::HmacSha1(o) => o.secret,
      _ => panic!("Expected HmacSha1 output"),
    };
    let response = crate::crypto::hmacsha1(&secret, &challenge);

    let result = hmacsha1(response);
    assert!(result.is_ok());
    result.unwrap().factor_type
  }

  #[test]
  fn include_params_missing_pad() {
    let setup = mock_hmac_setup();
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let mut setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::HmacSha1(p) => p,
      _ => panic!("Expected HmacSha1 params"),
    };
    setup_params.pad = String::new();

    let mut hmac = mock_hmac_derive(&setup, &setup_params);
    let err = hmac
      .include_params(crate::definitions::factor::FactorParams::HmacSha1(setup_params))
      .unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(_)));
  }

  #[test]
  fn include_params_invalid_pad_type() {
    let setup = mock_hmac_setup();
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let mut setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::HmacSha1(p) => p,
      _ => panic!("Expected HmacSha1 params"),
    };
    setup_params.pad = "not-hex".to_string();

    let mut hmac = mock_hmac_derive(&setup, &setup_params);
    let err = hmac
      .include_params(crate::definitions::factor::FactorParams::HmacSha1(setup_params))
      .unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(_)));
  }

  #[test]
  fn include_params_invalid_pad_element_type() {
    let setup = mock_hmac_setup();
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::HmacSha1(p) => p,
      _ => panic!("Expected HmacSha1 params"),
    };

    let mut hmac = mock_hmac_derive(&setup, &setup_params);
    hmac.include_params(crate::definitions::factor::FactorParams::HmacSha1(setup_params)).unwrap();
  }

  #[test]
  fn include_params() {
    let setup = mock_hmac_setup();
    let setup_hmac: &HmacSha1 = match &setup.factor_type {
      FactorType::HmacSha1(h) => h,
      _ => panic!(),
    };
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::HmacSha1(p) => p,
      _ => panic!("Expected HmacSha1 params"),
    };
    let mut hmac = mock_hmac_derive(&setup, &setup_params);

    let result =
      hmac.include_params(crate::definitions::factor::FactorParams::HmacSha1(setup_params.clone()));
    assert!(result.is_ok());

    let hmac_factor = match &hmac {
      FactorType::HmacSha1(h) => h,
      _ => panic!(),
    };

    assert_eq!(hmac_factor.padded_secret, setup_hmac.padded_secret);
  }

  #[test]
  fn params_derive_produces_valid_pad() {
    let setup = mock_hmac_setup();
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::HmacSha1(p) => p,
      _ => panic!("Expected HmacSha1 params"),
    };

    let mut hmac = mock_hmac_derive(&setup, &setup_params);
    hmac.include_params(crate::definitions::factor::FactorParams::HmacSha1(setup_params)).unwrap();

    let hmac_factor = match &hmac {
      FactorType::HmacSha1(h) => h,
      _ => panic!(),
    };

    let derive_params = match hmac.derive().params([0u8; 32].into()).unwrap() {
      crate::definitions::factor::FactorParams::HmacSha1(p) => p,
      _ => panic!("Expected HmacSha1 params"),
    };

    let challenge = hex::decode(&derive_params.challenge).unwrap();

    let pad = hex::decode(&derive_params.pad).unwrap();

    let response = crate::crypto::hmacsha1(&hmac_factor.padded_secret[..20], &challenge);
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(&response);

    let decrypted_secret = decrypt(pad, &padded_key);

    assert_eq!(decrypted_secret, hmac_factor.padded_secret);
  }

  #[test]
  fn output_derive_produces_correct_secret() {
    let setup = mock_hmac_setup();
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::HmacSha1(p) => p,
      _ => panic!("Expected HmacSha1 params"),
    };

    let mut derive_hmac = mock_hmac_derive(&setup, &setup_params);
    derive_hmac
      .include_params(crate::definitions::factor::FactorParams::HmacSha1(setup_params))
      .unwrap();

    let output = derive_hmac.derive().output();
    let secret = match output {
      crate::definitions::factor::FactorOutput::HmacSha1(o) => o.secret,
      _ => panic!("Expected HmacSha1 output"),
    };

    let derive_hmac_factor = match &derive_hmac {
      FactorType::HmacSha1(h) => h,
      _ => panic!(),
    };

    assert_eq!(secret, derive_hmac_factor.padded_secret);
  }
}
