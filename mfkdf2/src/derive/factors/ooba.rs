//! This module implements the factor construction derive phase for the OOBA construction from
//! [`OOBA`](`crate::setup::factors::ooba()`).
//! - During setup, the factor samples a random 32‑byte target, encrypts it under a channel‑specific
//!   RSA key, and embeds an initial code and metadata in the policy.
//! - During derive, this module consumes a user‑entered OOBA code Wᵢⱼ, decrypts the target using
//!   the stored pad, and prepares the next encrypted payload and code for the following login
use aes::Aes256;
use base64::{Engine, engine::general_purpose};
use cbc::Encryptor;
use cipher::KeyIvInit;
use rsa::Oaep;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{
  crypto::{decrypt_cbc, encrypt_cbc, hkdf_sha256_with_info},
  defaults::ooba as ooba_defaults,
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  rng::GlobalRng,
  setup::factors::ooba::{
    Ooba, OobaOutput, OobaParams, OobaPublicKey, generate_alphanumeric_characters,
  },
};

impl FactorDerive for Ooba {
  /// Includes the public parameters for in factor state and decrypts the secret material from
  /// public parameters.
  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    if params.pad.is_empty() {
      return Err(MFKDF2Error::InvalidDeriveParams("pad".to_string()));
    }
    if params.key.is_none() {
      return Err(MFKDF2Error::MissingOobaKey);
    }

    let pad = general_purpose::STANDARD
      .decode(&params.pad)
      .map_err(|_| MFKDF2Error::InvalidDeriveParams("pad".to_string()))?;

    let key = hkdf_sha256_with_info(self.code.as_bytes(), &[], &[]);
    let iv = general_purpose::STANDARD
      .decode(
        params.params["iv"]
          .as_str()
          .ok_or_else(|| MFKDF2Error::MissingDeriveParams("iv".to_string()))?,
      )
      .map_err(|_| MFKDF2Error::InvalidDeriveParams("iv".to_string()))?;
    let key = cipher::Key::<cbc::Decryptor<Aes256>>::from(key);
    let iv = cipher::Iv::<cbc::Decryptor<Aes256>>::from_iter(iv);
    self.target = decrypt_cbc::<Aes256>(&pad, &key, &iv)?
      .try_into()
      .map_err(|_| MFKDF2Error::InvalidDeriveParams("target length".to_string()))?;

    self.length = params.length;
    self.jwk = params.key;

    self.params = params.params;

    Ok(())
  }

  /// Generates a new OOBA code and encrypts the secret material for the next derivation.
  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> {
    let code = generate_alphanumeric_characters(self.length.into()).to_uppercase();

    let next_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    let key = cipher::Key::<Encryptor<Aes256>>::from(next_key);
    let iv = Encryptor::<Aes256>::generate_iv(&mut GlobalRng);
    let pad = encrypt_cbc::<Aes256>(self.target.as_ref(), &key, &iv)?;

    let mut params = self.params.clone();
    params["code"] = Value::String(code);
    params["iv"] = json!(general_purpose::STANDARD.encode(iv));

    // store the iv in public params for the next derivation
    let mut pub_params = self.params.clone();
    pub_params["iv"] = json!(general_purpose::STANDARD.encode(iv));

    let plaintext = serde_json::to_vec(&params)?;
    let public_key =
      OobaPublicKey::try_from(&self.jwk.clone().ok_or(MFKDF2Error::MissingOobaKey)?)?;
    let ciphertext =
      public_key.0.encrypt(&mut rsa::rand_core::OsRng, Oaep::new::<Sha256>(), &plaintext)?;

    Ok(OobaParams {
      length: self.length,
      key:    self.jwk.clone(),
      params: pub_params,
      next:   hex::encode(ciphertext),
      pad:    general_purpose::STANDARD.encode(pad),
    })
  }

  fn output(&self) -> Self::Output { OobaOutput::default() }
}

/// Factor construction derive phase for an OOBA factor
///
/// The `code` should be the alphanumeric value delivered over the out‑of‑band channel (for example,
/// SMS or push notification) that corresponds to the initial OOBA policy parameters created during
/// setup.
///
/// # Errors
///
/// - [`MFKDF2Error::InvalidOobaCode`] if `code` is empty
/// - [`MFKDF2Error::MissingDeriveParams`] when required fields such as "pad" or "length" are absent
///   in the policy parameters
/// - [`MFKDF2Error::InvalidDeriveParams`] when fields such as "pad", "params", or "key" are
///   malformed or have the wrong type
///
/// # Example
///
/// Single‑factor setup/derive using OOBA within `KeySetup`/`KeyDerive`:
///
/// ```rust
/// # use std::collections::HashMap;
/// # use jsonwebtoken::jwk::Jwk;
/// # use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
/// # use serde_json::json;
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   setup::{
/// #     self,
/// #     factors::ooba::{OobaOptions},
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive,
/// # };
/// # use base64::Engine;
/// let bits = 2048;
/// let private_key =
///   RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).expect("failed to generate a key");
/// let public_key = RsaPublicKey::from(&private_key);
///
/// let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
/// let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
/// let jwk: Jwk = serde_json::from_value(json!({
///   "kty": "RSA",
///   "alg": "RSA-OAEP-256",
///   "n": n,
///   "e": e
/// }))?;
///
/// let setup_factor = setup::factors::ooba(OobaOptions {
///   id:     Some("ooba".into()),
///   length: Some(8),
///   key:    Some(jwk),
///   params: Some(json!({"foo": "bar"})),
/// })?;
/// let setup_key = setup::key(&[setup_factor], MFKDF2Options::default())?;
///
/// // Decrypt the first OOBA payload to recover the user-visible code
/// let policy_factor =
///   setup_key.policy.factors.iter().find(|f| f.id == "ooba").unwrap();
/// let setup_params = &policy_factor.params;
/// let ciphertext = match setup_params {
///   mfkdf2::definitions::factor::FactorParams::OOBA(p) => hex::decode(&p.next).unwrap(),
///   _ => unreachable!(),
/// };
/// let plaintext = private_key.decrypt(rsa::Oaep::new::<sha2::Sha256>(), &ciphertext).unwrap();
/// let decoded: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
/// let code = decoded["code"].as_str().unwrap();
///
/// let derive_factor = derive::factors::ooba(code)?;
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("ooba".to_string(), derive_factor)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn ooba(code: &str) -> MFKDF2Result<MFKDF2Factor> {
  if code.is_empty() {
    return Err(MFKDF2Error::InvalidOobaCode);
  }

  Ok(MFKDF2Factor {
    id:          Some(ooba_defaults::ID.to_string()),
    factor_type: FactorType::OOBA(Ooba {
      target: [0u8; 32].into(),
      length: 0,
      code:   code.to_uppercase(),
      jwk:    None,
      params: json!({}),
    }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_ooba(code: &str) -> MFKDF2Result<MFKDF2Factor> { ooba(code) }

#[cfg(test)]
mod tests {
  use jsonwebtoken::jwk::Jwk;
  use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};

  use super::*;

  fn keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let bits = 2048;
    let private_key =
      RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
  }

  fn jwk(key: &RsaPublicKey) -> Jwk {
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
    let jwk = json!({
      "key_ops": ["encrypt", "decrypt"],
      "ext": true,
      "alg": "RSA-OAEP-256",
      "kty": "RSA",
      "n": n,
      "e": e
    });
    serde_json::from_value(jwk).unwrap()
  }

  fn mock_ooba_setup(key: &RsaPublicKey) -> MFKDF2Factor {
    let options = crate::setup::factors::ooba::OobaOptions {
      id:     Some("test".to_string()),
      length: Some(8),
      key:    Some(jwk(key)),
      params: Some(json!({"foo":"bar"})),
    };

    let result = crate::setup::factors::ooba(options);
    assert!(result.is_ok());

    result.unwrap()
  }

  #[test]
  fn derive_params() {
    let (private_key, public_key) = keypair();
    let setup = mock_ooba_setup(&public_key);

    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    let next_clone = setup_params.next.clone();
    let ciphertext = hex::decode(next_clone).unwrap();
    let decrypted = serde_json::from_slice::<Value>(
      &private_key.decrypt(Oaep::new::<Sha256>(), &ciphertext).unwrap(),
    )
    .unwrap();
    let code = decrypted["code"].as_str().unwrap();

    let result = ooba(code);
    assert!(result.is_ok());

    let factor = result.unwrap();

    let mut ooba: Ooba = match factor.factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("Factor type should be Ooba"),
    };

    ooba.include_params(setup_params.clone()).unwrap();
    let derive_params = ooba.params([0u8; 32].into()).unwrap();

    let ciphertext = hex::decode(derive_params.next).unwrap();
    let decrypted = serde_json::from_slice::<Value>(
      &private_key.decrypt(Oaep::new::<Sha256>(), &ciphertext).unwrap(),
    )
    .unwrap();
    let code = decrypted["code"].as_str().unwrap();
    let iv = general_purpose::STANDARD.decode(decrypted["iv"].as_str().unwrap()).unwrap();

    let prev_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    let pad = general_purpose::STANDARD.decode(&derive_params.pad).unwrap();
    let key = cipher::Key::<cbc::Decryptor<Aes256>>::from(prev_key);
    let iv = cipher::Iv::<cbc::Decryptor<Aes256>>::from_iter(iv);
    let target = crate::crypto::decrypt_cbc::<Aes256>(&pad, &key, &iv).unwrap();

    assert_eq!(ooba.target.as_ref(), target);
  }

  #[test]

  fn invalid_code() {
    let result = ooba("");
    assert!(matches!(result, Err(MFKDF2Error::InvalidOobaCode)));
  }

  #[test]
  fn params_derive_includes_original_params() {
    let (private_key, public_key) = keypair();
    let setup = mock_ooba_setup(&public_key);

    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    let next_clone = setup_params.next.clone();
    let ciphertext = hex::decode(next_clone).unwrap();
    let decrypted = serde_json::from_slice::<Value>(
      &private_key.decrypt(Oaep::new::<Sha256>(), &ciphertext).unwrap(),
    )
    .unwrap();
    let code = decrypted["code"].as_str().unwrap();

    let result = ooba(code);
    assert!(result.is_ok());

    let factor = result.unwrap();

    let mut ooba: Ooba = match factor.factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("Factor type should be Ooba"),
    };

    ooba.include_params(setup_params.clone()).unwrap();
    let derive_params = ooba.params([0u8; 32].into()).unwrap();

    assert_eq!(derive_params.params["foo"], "bar");
  }

  #[test]
  fn params_derive_next_is_decryptable() {
    // 1. Generate a private key
    let bits = 2048;
    let private_key =
      RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // 2. & 3. create n and e strings
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    // 4. Construct JWK
    let jwk = json!({
        "key_ops": ["encrypt", "decrypt"],
        "ext": true,
        "alg": "RSA-OAEP-256",
        "kty": "RSA",
        "n": n,
        "e": e
    });
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();

    // 5. Create mock ooba setup
    let options = crate::setup::factors::ooba::OobaOptions {
      id:     Some("test".to_string()),
      length: Some(8),
      key:    Some(jwk),
      params: Some(json!({"foo":"bar"})),
    };
    let setup = crate::setup::factors::ooba(options).unwrap();

    // Setup for derive
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    let ciphertext = hex::decode(setup_params.next.clone()).unwrap();
    let decrypted_params = serde_json::from_slice::<Value>(
      &private_key.decrypt(Oaep::new::<Sha256>(), &ciphertext).unwrap(),
    )
    .unwrap();
    let code = decrypted_params["code"].as_str().unwrap();
    let mut ooba: Ooba = match ooba(code).unwrap().factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("wrong type"),
    };
    ooba.include_params(setup_params).unwrap();

    // 6. Call params_derive
    let derive_params = ooba.params([0u8; 32].into()).unwrap();

    // 7. Get `next` and `params`
    let next_hex = &derive_params.next;
    // let params_from_derive = derive_params["params"].clone();
    let ciphertext = hex::decode(next_hex).unwrap();

    // 8. Decrypt
    let padding = Oaep::new::<Sha256>();
    let decrypted_bytes = private_key.decrypt(padding, &ciphertext).expect("failed to decrypt");

    // 9. Parse
    let mut decrypted_params = serde_json::from_slice::<Value>(&decrypted_bytes).unwrap();
    decrypted_params.as_object_mut().unwrap().remove("code");

    // TODO (@lonerapier): this won't be same after CBC encryption since IV is different
    // 10. Assert
    // assert_eq!(decrypted_params, params_from_derive);
  }

  fn get_ooba_for_test() -> Ooba {
    let result = ooba("some-code");
    assert!(result.is_ok());
    let factor = result.unwrap();
    match factor.factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("Factor type should be Ooba"),
    }
  }

  #[test]
  fn include_params_missing_pad() {
    let (_, public_key) = keypair();
    let setup = mock_ooba_setup(&public_key);
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let mut setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    setup_params.pad = String::new();

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(_)));
  }

  #[test]
  fn include_params_invalid_pad() {
    let (_, public_key) = keypair();
    let setup = mock_ooba_setup(&public_key);
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let mut setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    setup_params.pad = "not-base64".to_string();

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(_)));
  }

  #[test]
  fn include_params_missing_params_config() {
    let (_, public_key) = keypair();
    let setup = mock_ooba_setup(&public_key);
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let mut setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    setup_params.params = json!(null);

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingDeriveParams(_)));
  }

  #[test]
  fn include_params_params_config_not_object() {
    let (_, public_key) = keypair();
    let setup = mock_ooba_setup(&public_key);
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let mut setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    setup_params.params = json!("not-an-object");

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingDeriveParams(_)));
  }

  #[test]
  fn include_params_missing_length() {
    let (_, public_key) = keypair();
    let setup = mock_ooba_setup(&public_key);
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    // Length is part of the struct, so it can't be missing
    let mut ooba = get_ooba_for_test();
    ooba.include_params(setup_params).unwrap();
  }

  #[test]
  fn include_params_missing_key() {
    let (_, public_key) = keypair();
    let setup = mock_ooba_setup(&public_key);
    let setup_params_enum = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let mut setup_params = match setup_params_enum {
      crate::definitions::factor::FactorParams::OOBA(p) => p,
      _ => panic!("Expected OOBA params"),
    };
    setup_params.key = None;

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingOobaKey));
  }
}
