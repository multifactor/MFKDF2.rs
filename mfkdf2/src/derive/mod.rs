//! # MFKDF2 Key Derivation
//!
//! For i+1-th derivation of [`MFKDF2DerivedKey`](`crate::definitions::MFKDF2DerivedKey`),
//! [`KeyDerive`](`crate::derive::key::key`) takes every factor witnesses Wᵢⱼ and public state
//! βᵢⱼ (from key's inner state) and produces the updated key K and next state βᵢ₊₁
//!
//! # Factor Derive
//!
//! Derive algorithm for i-th derivation takes a j-th factor's witness Wᵢⱼ and the public
//! parameter βᵢⱼ and outputs the next state βᵢ₊₁,ⱼ and the source key material κⱼ.
//! `KeyDerive` performs this for every factor (up to the threshold). During Derive, the factor's
//! witness W is combined with public helper data to reconstruct the static κ. Thus, σ is the
//! underlying secret that "powers" the factor, while κ is the consistent value that the factor
//! contributes to the final key derivation.
pub mod factors;
mod key;

pub use key::key;

use crate::{definitions::Key, error::MFKDF2Result, traits::Factor};

/// Trait for factor derive.  
pub(crate) trait FactorDerive: Factor {
  /// Includes the public parameters and witness for the factor derive in factor state
  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()>;
  /// Returns the public parameters for the factor derive.
  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params>;
  /// Returns the public output for the factor derive.
  fn output(&self) -> Self::Output;
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derive_factor_params(
  factor: &crate::definitions::FactorType,
  key: Option<Key>,
) -> MFKDF2Result<crate::definitions::factor::FactorParams> {
  let key = key.unwrap_or_else(|| [0u8; 32].into());
  factor.derive().params(key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derive_factor_output(factor: &crate::definitions::FactorType) -> serde_json::Value {
  factor.derive().output()
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use base64::Engine;
  use rsa::traits::PublicKeyParts;
  use serde_json::json;

  use crate::{
    definitions::{MFKDF2DerivedKey, MFKDF2Options},
    derive,
    setup::{
      self,
      factors::{
        hmacsha1::{HmacSha1Options, HmacSha1Output, HmacSha1Response},
        ooba::OobaOptions,
        stack::StackOptions,
        uuid::UUIDOptions,
      },
    },
  };

  #[test]
  fn derive_outputs_stack() {
    let setup = setup::key(
      &[setup::factors::stack(
        vec![
          setup::factors::uuid(UUIDOptions {
            id:   Some("uuid1".to_string()),
            uuid: Some(uuid::Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
          })
          .unwrap(),
          setup::factors::uuid(UUIDOptions {
            id:   Some("uuid2".to_string()),
            uuid: Some(uuid::Uuid::parse_str("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed").unwrap()),
          })
          .unwrap(),
          setup::factors::uuid(UUIDOptions {
            id:   Some("uuid3".to_string()),
            uuid: Some(uuid::Uuid::parse_str("6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b").unwrap()),
          })
          .unwrap(),
        ],
        StackOptions::default(),
      )
      .unwrap()],
      MFKDF2Options::default(),
    )
    .unwrap();

    let mut setup_key: MFKDF2DerivedKey =
      serde_json::from_value(setup.outputs["stack"].clone()).unwrap();
    setup_key.entropy.real = 0.0;
    setup_key.entropy.theoretical = 0;

    let derive = derive::key(
      &setup.policy,
      HashMap::from([(
        "stack".to_string(),
        derive::factors::stack(HashMap::from([
          (
            "uuid1".to_string(),
            derive::factors::uuid(
              uuid::Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap(),
            )
            .unwrap(),
          ),
          (
            "uuid2".to_string(),
            derive::factors::uuid(
              uuid::Uuid::parse_str("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed").unwrap(),
            )
            .unwrap(),
          ),
          (
            "uuid3".to_string(),
            derive::factors::uuid(
              uuid::Uuid::parse_str("6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b").unwrap(),
            )
            .unwrap(),
          ),
        ]))
        .unwrap(),
      )]),
      true,
      false,
    )
    .unwrap();

    let factor_output: MFKDF2DerivedKey =
      serde_json::from_value(derive.outputs["stack"].clone()).unwrap();
    assert_eq!(setup_key, factor_output);
  }

  #[test]
  fn derive_outputs_hmacsha1() {
    let setup = setup::key(
      &[setup::factors::hmacsha1(HmacSha1Options::default()).unwrap()],
      MFKDF2Options::default(),
    )
    .unwrap();

    let setup_output: HmacSha1Output =
      serde_json::from_value(setup.outputs["hmacsha1"].clone()).unwrap();
    let params = &setup.policy.factors.iter().find(|f| f.id == "hmacsha1").unwrap().params;
    let challenge = match params {
      crate::definitions::factor::FactorParams::HmacSha1(p) => hex::decode(&p.challenge).unwrap(),
      _ => panic!("Expected HmacSha1 params"),
    };

    let response = crate::crypto::hmacsha1(&setup_output.secret, &challenge);

    let derive = derive::key(
      &setup.policy,
      HashMap::from([(
        "hmacsha1".to_string(),
        derive::factors::hmacsha1(HmacSha1Response::from(response)).unwrap(),
      )]),
      true,
      false,
    )
    .unwrap();

    assert_ne!(setup.outputs, derive.outputs);
  }

  #[test]
  fn derive_outputs_uuid() {
    let setup = setup::key(
      &[setup::factors::uuid(UUIDOptions {
        uuid: Some(uuid::Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
        id:   None,
      })
      .unwrap()],
      MFKDF2Options::default(),
    )
    .unwrap();

    let derive = derive::key(
      &setup.policy,
      HashMap::from([(
        "uuid".to_string(),
        derive::factors::uuid(
          uuid::Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap(),
        )
        .unwrap(),
      )]),
      true,
      false,
    )
    .unwrap();

    assert_eq!(setup.outputs, derive.outputs);
  }

  #[test]
  fn derive_outputs_question() {
    let setup = setup::key(
      &[setup::factors::question(
        "Fido",
        crate::setup::factors::question::QuestionOptions::default(),
      )
      .unwrap()],
      MFKDF2Options::default(),
    )
    .unwrap();

    let derive = derive::key(
      &setup.policy,
      HashMap::from([("question".to_string(), derive::factors::question("Fido").unwrap())]),
      true,
      false,
    )
    .unwrap();

    let setup_output_json = serde_json::to_value(setup.outputs["question"].clone()).unwrap();
    let derive_output_json = serde_json::to_value(derive.outputs["question"].clone()).unwrap();

    // remove calc_time from both outputs
    let mut setup_output = setup_output_json["strength"].clone();
    let mut derive_output = derive_output_json["strength"].clone();
    setup_output.as_object_mut().unwrap().remove("calc_time");
    derive_output.as_object_mut().unwrap().remove("calc_time");

    assert_eq!(setup_output, derive_output);
  }

  #[test]
  fn derive_outputs_ooba() {
    let bits = 2048;
    let private_key =
      rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).expect("failed to generate a key");
    let public_key = rsa::RsaPublicKey::from(&private_key);

    // 2. & 3. create n and e strings
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    // 4. Construct JWK
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(json!({
        "key_ops": ["encrypt", "decrypt"],
        "ext": true,
        "alg": "RSA-OAEP-256",
        "kty": "RSA",
        "n": n,
        "e": e
    }))
    .unwrap();

    let setup = setup::key(
      &[setup::factors::ooba(OobaOptions {
        key: Some(jwk),
        params: Some(json!({ "email": "test@mfkdf.com" })),
        ..Default::default()
      })
      .unwrap()],
      MFKDF2Options::default(),
    )
    .unwrap();

    let params = &setup.policy.factors[0].params;
    let next = match params {
      crate::definitions::factor::FactorParams::OOBA(p) => hex::decode(&p.next).unwrap(),
      _ => panic!("Expected OOBA params"),
    };

    let decrypted = serde_json::from_slice::<serde_json::Value>(
      &private_key.decrypt(rsa::Oaep::new::<sha2::Sha256>(), &next).unwrap(),
    )
    .unwrap();
    let code = decrypted["code"].as_str().unwrap();

    let derive = derive::key(
      &setup.policy,
      HashMap::from([("ooba".to_string(), derive::factors::ooba(code).unwrap())]),
      true,
      false,
    )
    .unwrap();

    assert_eq!(setup.outputs, derive.outputs);
  }

  #[test]
  fn derive_outputs_password() {
    let setup = setup::key(
      &[setup::factors::password(
        "password",
        crate::setup::factors::password::PasswordOptions::default(),
      )
      .unwrap()],
      MFKDF2Options::default(),
    )
    .unwrap();

    let derive = derive::key(
      &setup.policy,
      HashMap::from([("password".to_string(), derive::factors::password("password").unwrap())]),
      true,
      false,
    )
    .unwrap();

    let setup_output_json = serde_json::to_value(setup.outputs["password"].clone()).unwrap();
    let derive_output_json = serde_json::to_value(derive.outputs["password"].clone()).unwrap();
    let mut setup_output = setup_output_json["strength"].clone();
    let mut derive_output = derive_output_json["strength"].clone();
    setup_output.as_object_mut().unwrap().remove("calc_time");
    derive_output.as_object_mut().unwrap().remove("calc_time");
    assert_eq!(setup_output, derive_output);
  }

  #[test]
  fn derive_outputs_multiple() {
    let setup = setup::key(
      &[
        setup::factors::uuid(UUIDOptions {
          uuid: Some(uuid::Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap()),
          id:   Some("uuid1".to_string()),
        })
        .unwrap(),
        setup::factors::uuid(UUIDOptions {
          uuid: Some(uuid::Uuid::parse_str("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed").unwrap()),
          id:   Some("uuid2".to_string()),
        })
        .unwrap(),
        setup::factors::uuid(UUIDOptions {
          uuid: Some(uuid::Uuid::parse_str("6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b").unwrap()),
          id:   Some("uuid3".to_string()),
        })
        .unwrap(),
      ],
      MFKDF2Options { threshold: Some(2), ..Default::default() },
    )
    .unwrap();

    assert_eq!(
      setup.outputs,
      HashMap::from([
        (
          "uuid1".to_string(),
          serde_json::json!({
            "uuid": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
          })
        ),
        (
          "uuid2".to_string(),
          serde_json::json!({
            "uuid": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
          })
        ),
        (
          "uuid3".to_string(),
          serde_json::json!({
            "uuid": "6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b",
          })
        ),
      ])
    );

    let derive = derive::key(
      &setup.policy,
      HashMap::from([
        (
          "uuid1".to_string(),
          derive::factors::uuid(
            uuid::Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap(),
          )
          .unwrap(),
        ),
        (
          "uuid3".to_string(),
          derive::factors::uuid(
            uuid::Uuid::parse_str("6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b").unwrap(),
          )
          .unwrap(),
        ),
      ]),
      true,
      false,
    )
    .unwrap();

    assert_eq!(
      derive.outputs,
      HashMap::from([
        (
          "uuid1".to_string(),
          serde_json::json!({
            "uuid": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
          })
        ),
        (
          "uuid3".to_string(),
          serde_json::json!({
            "uuid": "6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b",
          })
        ),
      ])
    );
  }
}
