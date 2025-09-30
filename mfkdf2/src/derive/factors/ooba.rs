use base64::{Engine, engine::general_purpose};
use rand::rngs::OsRng;
use rsa::Oaep;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{
  crypto::{decrypt, encrypt, hkdf_sha256_with_info},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{
    FactorType, MFKDF2Factor,
    ooba::{Ooba, OobaPublicKey, generate_alphanumeric_characters},
  },
};

impl FactorDerive for Ooba {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    let pad_b64 =
      params["pad"].as_str().ok_or(MFKDF2Error::MissingDeriveParams("pad".to_string()))?;
    let pad = general_purpose::STANDARD
      .decode(pad_b64)
      .map_err(|_| MFKDF2Error::InvalidDeriveParams("pad".to_string()))?;

    let config = params["params"].clone();
    if !config.is_object() {
      return Err(MFKDF2Error::InvalidDeriveParams("params".to_string()));
    }

    let code =
      config["code"].as_str().ok_or(MFKDF2Error::MissingDeriveParams("code".to_string()))?;

    let key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    self.target = decrypt(pad, &key);

    self.length = params["length"]
      .as_u64()
      .ok_or(MFKDF2Error::MissingDeriveParams("length".to_string()))? as u8;
    self.jwk = params["key"]
      .as_str()
      .ok_or(MFKDF2Error::MissingDeriveParams("key".to_string()))?
      .to_string();

    self.params = serde_json::to_string(&config).unwrap();

    Ok(())
  }

  fn params(&self, _key: [u8; 32]) -> Value {
    let code = generate_alphanumeric_characters(self.length.into()).to_uppercase();

    let next_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    let pad = encrypt(&self.target, &next_key);

    let mut params: Value = match serde_json::from_str(&self.params) {
      Ok(p) => p,
      Err(_) => json!({}),
    };
    params["code"] = serde_json::Value::String(code);

    let plaintext = serde_json::to_vec(&params).expect("Should serialize params to bytes");
    let public_key = OobaPublicKey::try_from(self.jwk.as_ref()).expect("JWK should be valid");
    let ciphertext = public_key
      .0
      .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &plaintext)
      .expect("Should encrypt params");

    json!({
        "length": self.length,
        "key": self.jwk,
        "params": params,
        "next": hex::encode(ciphertext),
        "pad": general_purpose::STANDARD.encode(pad),
    })
  }

  fn output(&self) -> Value { json!({}) }
}

pub fn ooba(code: String) -> MFKDF2Result<MFKDF2Factor> {
  if code.is_empty() {
    return Err(MFKDF2Error::InvalidOobaCode);
  }

  Ok(MFKDF2Factor {
    id:          Some("ooba".to_string()),
    factor_type: FactorType::OOBA(Ooba {
      target: vec![],
      length: 0,
      jwk:    "".to_string(),
      params: "".to_string(),
    }),
    salt:        [0u8; 32].to_vec(),
    entropy:     None,
  })
}

#[uniffi::export]
pub fn derive_ooba(code: String) -> MFKDF2Result<MFKDF2Factor> { ooba(code) }

#[cfg(test)]
mod tests {
  use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};

  use super::*;

  const TEST_JWK: &str = r#"{
    "key_ops": ["encrypt", "decrypt"],
    "ext": true,
    "alg": "RSA-OAEP-256",
    "kty": "RSA",
    "n": "1jR1L4H7Wov2W3XWlw1OII-fh_YuzfbZgpMCeSIPUd5oPvyvRf8nshkclQ9EQy6QlCZPX0HzCqkGokppxirKisyjfAlremiL8H60t2aapN_T3eClJ3KUxyEO1cejWoKejD86OtL_DWc04odInpcRmFgAF8mgjbEZRD0oSzaGlr70Ezi8p0yhpMTFM2Ltn0LG6SJ2_LGQwpEFNFf7790IoNpx8vKIZq0Ok1dGhC808f2t0ZhVFmxYnR-fp1jxd5B9nYDkjyJbWQK4vPlpAOgHw9v8G2Cg2X1TX2Ywr19tB249es2NlOYrFRQugzPyKfuVYxpFgoJfMuP83SPx-RvK6w",
    "e": "AQAB"
  }"#;

  fn mock_ooba_setup() -> MFKDF2Factor {
    let options = crate::setup::factors::ooba::OobaOptions {
      id:     Some("test".to_string()),
      length: 8,
      key:    Some(TEST_JWK.to_string()),
      params: Some(r#"{"foo":"bar"}"#.to_string()),
    };

    let result = crate::setup::factors::ooba::ooba(options);
    assert!(result.is_ok());

    result.unwrap()
  }

  #[test]
  fn derive_params() {
    let setup = mock_ooba_setup();

    let setup_params = setup.factor_type.setup().params([0u8; 32].into());
    let code = setup_params["params"]["code"].as_str().unwrap();

    let result = ooba(code.to_string());
    assert!(result.is_ok());

    let factor = result.unwrap();

    let mut ooba: Ooba = match factor.factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("Factor type should be Ooba"),
    };

    ooba.include_params(setup_params).unwrap();
    let derive_params = ooba.params([0u8; 32].into());

    let code = derive_params["params"]["code"].as_str().unwrap();

    let prev_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    let pad = general_purpose::STANDARD.decode(derive_params["pad"].as_str().unwrap()).unwrap();
    let target = decrypt(pad, &prev_key);

    assert_eq!(ooba.target, target);
  }

  #[test]

  fn invalid_code() {
    let result = ooba(String::from(""));
    assert!(matches!(result, Err(MFKDF2Error::InvalidOobaCode)));
  }

  #[test]
  fn params_derive_includes_original_params() {
    let setup = mock_ooba_setup();

    let setup_params = setup.factor_type.setup().params([0u8; 32].into());
    let code = setup_params["params"]["code"].as_str().unwrap();

    let result = ooba(code.to_string());
    assert!(result.is_ok());

    let factor = result.unwrap();

    let mut ooba: Ooba = match factor.factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("Factor type should be Ooba"),
    };

    ooba.include_params(setup_params).unwrap();
    let derive_params = ooba.params([0u8; 32].into());

    assert_eq!(derive_params["params"]["foo"], "bar");
  }

  #[test]
  fn params_derive_next_is_decryptable() {
    // 1. Generate a private key
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut OsRng, bits).expect("failed to generate a key");
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
    })
    .to_string();

    // 5. Create mock ooba setup
    let options = crate::setup::factors::ooba::OobaOptions {
      id:     Some("test".to_string()),
      length: 8,
      key:    Some(jwk),
      params: Some(r#"{"foo":"bar"}"#.to_string()),
    };
    let setup = crate::setup::factors::ooba::ooba(options).unwrap();

    // Setup for derive
    let setup_params = setup.factor_type.setup().params([0u8; 32].into());
    let code = setup_params["params"]["code"].as_str().unwrap();
    let mut ooba: Ooba = match ooba(code.to_string()).unwrap().factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("wrong type"),
    };
    ooba.include_params(setup_params).unwrap();

    // 6. Call params_derive
    let derive_params = ooba.params([0u8; 32].into());

    // 7. Get `next` and `params`
    let next_hex = derive_params["next"].as_str().unwrap();
    let params_from_derive = derive_params["params"].clone();
    let ciphertext = hex::decode(next_hex).unwrap();

    // 8. Decrypt
    let padding = Oaep::new::<Sha256>();
    let decrypted_bytes = private_key.decrypt(padding, &ciphertext).expect("failed to decrypt");

    // 9. Parse
    let decrypted_params: Value = serde_json::from_slice(&decrypted_bytes).unwrap();

    // 10. Assert
    assert_eq!(decrypted_params, params_from_derive);
  }

  fn get_ooba_for_test() -> Ooba {
    let result = ooba("some-code".to_string());
    assert!(result.is_ok());
    let factor = result.unwrap();
    match factor.factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("Factor type should be Ooba"),
    }
  }

  #[test]
  fn include_params_missing_pad() {
    let setup = mock_ooba_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into());
    setup_params.as_object_mut().unwrap().remove("pad");

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingDeriveParams(s) if s == "pad"));
  }

  #[test]
  fn include_params_invalid_pad() {
    let setup = mock_ooba_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into());
    setup_params["pad"] = json!("not-base64");

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(s) if s == "pad"));
  }

  #[test]
  fn include_params_missing_params_config() {
    let setup = mock_ooba_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into());
    setup_params.as_object_mut().unwrap().remove("params");

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(s) if s == "params"));
  }

  #[test]
  fn include_params_params_config_not_object() {
    let setup = mock_ooba_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into());
    setup_params["params"] = json!("not-an-object");

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(s) if s == "params"));
  }

  #[test]
  fn include_params_missing_code() {
    let setup = mock_ooba_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into());
    setup_params["params"].as_object_mut().unwrap().remove("code");

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingDeriveParams(s) if s == "code"));
  }

  #[test]
  fn include_params_missing_length() {
    let setup = mock_ooba_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into());
    setup_params.as_object_mut().unwrap().remove("length");

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingDeriveParams(s) if s == "length"));
  }

  #[test]
  fn include_params_missing_key() {
    let setup = mock_ooba_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into());
    setup_params.as_object_mut().unwrap().remove("key");

    let mut ooba = get_ooba_for_test();
    let err = ooba.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingDeriveParams(s) if s == "key"));
  }
}
