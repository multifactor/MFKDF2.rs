use base64::{Engine, engine::general_purpose};
use jsonwebtoken::jwk::Jwk;
use rand::{Rng, RngCore, rngs::OsRng};
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{
  crypto::{encrypt, hkdf_sha256_with_info},
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorMetadata, FactorSetup, FactorType, MFKDF2Factor},
};

pub fn generate_alphanumeric_characters(length: u32) -> String {
  (0..length)
    .map(|_| {
      let n: u8 = OsRng.gen_range(0..36); // 0–35
      char::from_digit(n as u32, 36).unwrap() // base-36 => 0–9, a–z
    })
    .collect()
}

pub struct OobaPublicKey(pub RsaPublicKey);

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct OobaOptions {
  pub id:     Option<String>,
  pub length: u8,
  pub key:    Option<String>, // TODO (sambhav): move to uniffi custom types
  pub params: Option<String>,
}

impl Default for OobaOptions {
  fn default() -> Self { Self { id: Some("ooba".to_string()), length: 6, key: None, params: None } }
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Ooba {
  pub target: Vec<u8>,
  // TODO (@lonerapier): this looks like a security bug
  pub code:   String,
  pub length: u8,
  pub jwk:    String,
  pub params: String,
}

impl TryFrom<&str> for OobaPublicKey {
  type Error = MFKDF2Error;

  fn try_from(key: &str) -> Result<Self, Self::Error> {
    let jwk: Jwk = serde_json::from_str(key).map_err(MFKDF2Error::SerializeError)?;

    let n_str = match &jwk.algorithm {
      jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa_params) => &rsa_params.n,
      _ => return Err(MFKDF2Error::InvalidOobaKey),
    };
    let e_str = match &jwk.algorithm {
      jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa_params) => &rsa_params.e,
      _ => return Err(MFKDF2Error::InvalidOobaKey),
    };

    let n = rsa::BigUint::from_bytes_be(
      &base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n_str)
        .map_err(MFKDF2Error::DecodeError)?,
    );
    let e = rsa::BigUint::from_bytes_be(
      &base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(e_str)
        .map_err(MFKDF2Error::DecodeError)?,
    );

    Ok(OobaPublicKey(RsaPublicKey::new(n, e).map_err(|_| MFKDF2Error::InvalidOobaKey)?))
  }
}

impl FactorMetadata for Ooba {
  fn kind(&self) -> String { "ooba".to_string() }
}

impl FactorSetup for Ooba {
  fn bytes(&self) -> Vec<u8> { self.target.clone() }

  fn params(&self, _key: [u8; 32]) -> Value {
    let code = generate_alphanumeric_characters(self.length.into()).to_uppercase();

    let prev_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    let pad = encrypt(&self.target, &prev_key);

    let mut params = match serde_json::from_str(&self.params) {
      Ok(params) => params,
      Err(_) => json!({}),
    };
    params["code"] = json!(code);

    let plaintext = serde_json::to_vec(&params).expect("Should serialize params to bytes");
    let key = OobaPublicKey::try_from(self.jwk.as_str()).expect("JWK should be valid");
    let ciphertext =
      key.0.encrypt(&mut OsRng, Oaep::new::<Sha256>(), &plaintext).expect("Should encrypt params");

    json!({
        "length": self.length,
        "key": self.jwk,
        "params": params,
        "next": hex::encode(ciphertext),
        "pad": general_purpose::STANDARD.encode(pad),
    })
  }

  fn output(&self, _key: [u8; 32]) -> Value { json!({}) }
}

pub fn ooba(options: OobaOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let length = options.length;
  if length == 0 || length > 32 {
    return Err(MFKDF2Error::InvalidOobaLength);
  }

  let params = if let Some(params) = options.params {
    params
  } else {
    let params = json!({});
    params.to_string()
  };

  let key: Jwk = if let Some(ref key) = options.key {
    serde_json::from_str(key).map_err(MFKDF2Error::SerializeError)?
  } else {
    return Err(MFKDF2Error::MissingOobaKey);
  };
  // verify that key is rsa public key
  if !matches!(key.algorithm, jsonwebtoken::jwk::AlgorithmParameters::RSA(_)) {
    return Err(MFKDF2Error::InvalidOobaKey);
  }

  // Generate 32-byte random target (the factor's data)
  let mut target = [0u8; 32];
  OsRng.fill_bytes(&mut target);

  // Random salt to align with other factors shape
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MFKDF2Factor {
    id:          Some(options.id.unwrap_or("ooba".to_string())),
    salt:        salt.to_vec(),
    factor_type: FactorType::OOBA(Ooba {
      code: String::new(),
      target: target.to_vec(),
      length,
      jwk: options.key.unwrap(),
      params,
    }),
    entropy:     Some((length as f64 * 36f64.log2()).round() as u32),
  })
}

#[uniffi::export]
pub fn setup_ooba(options: OobaOptions) -> MFKDF2Result<MFKDF2Factor> { ooba(options) }

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::decrypt;

  const TEST_JWK: &str = r#"{
    "key_ops": ["encrypt", "decrypt"],
    "ext": true,
    "alg": "RSA-OAEP-256",
    "kty": "RSA",
    "n": "1jR1L4H7Wov2W3XWlw1OII-fh_YuzfbZgpMCeSIPUd5oPvyvRf8nshkclQ9EQy6QlCZPX0HzCqkGokppxirKisyjfAlremiL8H60t2aapN_T3eClJ3KUxyEO1cejWoKejD86OtL_DWc04odInpcRmFgAF8mgjbEZRD0oSzaGlr70Ezi8p0yhpMTFM2Ltn0LG6SJ2_LGQwpEFNFf7790IoNpx8vKIZq0Ok1dGhC808f2t0ZhVFmxYnR-fp1jxd5B9nYDkjyJbWQK4vPlpAOgHw9v8G2Cg2X1TX2Ywr19tB249es2NlOYrFRQugzPyKfuVYxpFgoJfMuP83SPx-RvK6w",
    "e": "AQAB"
  }"#;

  fn mock_construction() -> MFKDF2Factor {
    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: 8,
      key:    Some(TEST_JWK.to_string()),
      params: Some(r#"{"foo":"bar"}"#.to_string()),
    };

    let result = ooba(options);
    assert!(result.is_ok());

    result.unwrap()
  }

  #[test]
  fn construction() {
    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: 8,
      key:    Some(TEST_JWK.to_string()),
      params: Some(r#"{"foo":"bar"}"#.to_string()),
    };

    let result = ooba(options);
    assert!(result.is_ok());

    let factor = result.unwrap();
    assert_eq!(factor.id, Some("test".to_string()));
    assert_eq!(factor.salt.len(), 32);

    assert!(matches!(factor.factor_type, FactorType::OOBA(_)));
    if let FactorType::OOBA(ooba_factor) = factor.factor_type {
      assert_eq!(ooba_factor.length, 8);
      assert_eq!(ooba_factor.jwk, TEST_JWK.to_string());
      assert_eq!(ooba_factor.params, r#"{"foo":"bar"}"#.to_string());
      assert_eq!(ooba_factor.target.len(), 32);
    }
  }

  #[test]
  fn empty_id() {
    let options = OobaOptions {
      id:     Some("".to_string()),
      length: 6,
      key:    Some(TEST_JWK.to_string()),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::MissingFactorId)));
  }

  #[test]
  fn zero_length() {
    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: 0,
      key:    Some(TEST_JWK.to_string()),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidOobaLength)));
  }

  #[test]
  fn large_length() {
    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: 33,
      key:    Some(TEST_JWK.to_string()),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidOobaLength)));
  }

  #[test]
  fn missing_key() {
    let options =
      OobaOptions { id: Some("test".to_string()), length: 6, key: None, params: None };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::MissingOobaKey)));
  }

  #[test]
  fn invalid_key_format() {
    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: 6,
      key:    Some("not-a-jwk".to_string()),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::SerializeError(_))));
  }

  #[test]
  fn not_rsa_key() {
    const TEST_EC_JWK: &str = r#"{
      "kty": "EC",
      "crv": "P-256",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvlogunL7_vC1Gja-9XRUPKnsI"
    }"#;

    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: 6,
      key:    Some(TEST_EC_JWK.to_string()),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidOobaKey)));
  }

  #[test]
  fn params() {
    let factor = mock_construction();

    let ooba: Ooba = match factor.factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("Factor type should be Ooba"),
    };

    let params = ooba.params([0u8; 32]);
    assert!(params.is_object());

    // check params.next is equal to params.params
    let setup_params = params["params"].clone();

    let code = setup_params["code"].as_str().unwrap();

    let prev_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    let pad = general_purpose::STANDARD.decode(params["pad"].as_str().unwrap()).unwrap();
    let target = decrypt(pad, &prev_key);

    assert_eq!(ooba.target, target);
  }

  #[test]
  fn output() {
    let factor = mock_construction();
    let output = factor.factor_type.output([0u8; 32]);
    assert!(output.is_object());
  }
}
