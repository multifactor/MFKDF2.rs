use base64::{Engine, engine::general_purpose};
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPublicKey};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{
  crypto::{decrypt, encrypt, hkdf_sha256_with_info},
  derive::{FactorDeriveTrait, factors::MFKDF2DeriveFactor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{
    FactorType,
    ooba::{Ooba, generate_alphanumeric_characters, rsa_publickey_from_jwk},
  },
};

impl FactorDeriveTrait for Ooba {
  fn kind(&self) -> String { "ooba".to_string() }

  fn bytes(&self) -> Vec<u8> { self.target.clone() }

  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    let pad_b64 =
      params["pad"].as_str().ok_or(MFKDF2Error::MissingDeriveParams("pad".to_string()))?;
    let pad = general_purpose::STANDARD
      .decode(pad_b64)
      .map_err(|_| MFKDF2Error::InvalidDeriveParams("pad".to_string()))?;

    let key = hkdf_sha256_with_info(self.code.as_bytes(), &[], &[]);
    self.target = decrypt(pad, &key);

    self.length = params["length"]
      .as_u64()
      .ok_or(MFKDF2Error::MissingDeriveParams("length".to_string()))? as u8;
    self.jwk = params["key"]
      .as_str()
      .ok_or(MFKDF2Error::MissingDeriveParams("key".to_string()))?
      .to_string();

    self.params = serde_json::to_string(&params).unwrap();

    Ok(())
  }

  fn params_derive(&self, _key: [u8; 32]) -> Value {
    let code = generate_alphanumeric_characters(self.length.into()).to_uppercase();

    let next_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    let pad = encrypt(&self.target, &next_key);

    let mut params: Value = match serde_json::from_str(&self.params) {
      Ok(p) => p,
      Err(_) => json!({}),
    };
    params["code"] = serde_json::Value::String(code);

    let plaintext = serde_json::to_vec(&params).expect("Should serialize params to bytes");
    let public_key: RsaPublicKey = rsa_publickey_from_jwk(&self.jwk);
    let ciphertext = public_key
      .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &plaintext)
      .expect("Should encrypt params");

    json!({
        "length": self.length,
        "key": self.jwk,
        "params": self.params,
        "next": hex::encode(ciphertext),
        "pad": general_purpose::STANDARD.encode(pad),
    })
  }

  fn output_derive(&self, _key: [u8; 32]) -> Value { json!({}) }
}

pub fn ooba(code: String) -> MFKDF2Result<MFKDF2DeriveFactor> {
  if code.is_empty() {
    return Err(MFKDF2Error::InvalidOobaCode);
  }

  Ok(MFKDF2DeriveFactor {
    id:          Some("ooba".to_string()),
    factor_type: FactorType::OOBA(Ooba {
      code:   code.to_uppercase(),
      target: vec![],
      length: 0,
      jwk:    "".to_string(),
      params: "".to_string(),
    }),
    salt:        [0u8; 32].to_vec(),
    entropy:     None,
  })
}
