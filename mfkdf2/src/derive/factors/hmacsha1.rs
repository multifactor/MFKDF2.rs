use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};

use crate::{
  crypto::{decrypt, encrypt},
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::MFKDF2Result,
  setup::factors::hmacsha1::{HmacSha1, HmacSha1Response},
};

impl FactorDerive for HmacSha1 {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    self.params = Some(serde_json::to_string(&params).unwrap());

    let response = self.response.as_ref().unwrap();
    let mut padded_key = [0u8; 32];
    padded_key[..response.0.len()].copy_from_slice(&response.0);

    let pad = hex::decode(
      params
        .get("pad")
        .ok_or_else(|| crate::error::MFKDF2Error::MissingDeriveParams("pad".to_string()))?
        .as_str()
        .ok_or(crate::error::MFKDF2Error::InvalidDeriveParams("pad".to_string()))?,
    )
    .map_err(|e| crate::error::MFKDF2Error::InvalidDeriveParams(e.to_string()))?;

    let padded_secret = decrypt(pad, &padded_key);
    self.padded_secret = padded_secret;

    Ok(())
  }

  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> {
    let mut challenge = [0u8; 64];
    OsRng.fill_bytes(&mut challenge);

    let response = crate::crypto::hmacsha1(&self.padded_secret[..20], &challenge);
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(&response);
    let pad = encrypt(&self.padded_secret, &padded_key);

    Ok(json!({
      "challenge": hex::encode(challenge),
      "pad": hex::encode(pad),
    }))
  }

  fn output(&self) -> Self::Output {
    json!({
      "secret": self.padded_secret,
    })
  }
}

pub fn hmacsha1(response: HmacSha1Response) -> MFKDF2Result<MFKDF2Factor> {
  Ok(MFKDF2Factor {
    id:          None,
    factor_type: FactorType::HmacSha1(HmacSha1 {
      response:      Some(response),
      params:        None,
      padded_secret: [0u8; 32].to_vec(),
    }),
    salt:        [0u8; 32].to_vec(),
    entropy:     Some(160.0),
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn derive_hmacsha1(response: HmacSha1Response) -> MFKDF2Result<MFKDF2Factor> {
  crate::derive::factors::hmacsha1(response)
}

#[cfg(test)]
mod tests {
  use serde_json::json;

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

  fn mock_hmac_derive(setup_factor: &MFKDF2Factor, setup_params: &Value) -> FactorType {
    let challenge = hex::decode(setup_params.get("challenge").unwrap().as_str().unwrap()).unwrap();
    let secret = setup_factor
      .factor_type
      .setup()
      .output([0u8; 32].into())
      .get("secret")
      .unwrap()
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_u64().unwrap() as u8)
      .collect::<Vec<u8>>();
    let response = crate::crypto::hmacsha1(&secret, &challenge);

    let result = hmacsha1(response.into());
    assert!(result.is_ok());
    result.unwrap().factor_type
  }

  #[test]
  fn include_params_missing_pad() {
    let setup = mock_hmac_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    setup_params.as_object_mut().unwrap().remove("pad");

    let mut hmac = mock_hmac_derive(&setup, &setup_params);
    let err = hmac.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::MissingDeriveParams(s) if s == "pad"));
  }

  #[test]
  fn include_params_invalid_pad_type() {
    let setup = mock_hmac_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    setup_params["pad"] = json!("not-an-array");

    let mut hmac = mock_hmac_derive(&setup, &setup_params);
    let err = hmac.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(s) if s.contains("Invalid character")));
  }

  #[test]
  fn include_params_invalid_pad_element_type() {
    let setup = mock_hmac_setup();
    let mut setup_params = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    setup_params["pad"] = json!(["not-a-number"]);

    let mut hmac = mock_hmac_derive(&setup, &setup_params);
    let err = hmac.include_params(setup_params).unwrap_err();
    assert!(matches!(err, MFKDF2Error::InvalidDeriveParams(s) if s == "pad"));
  }

  #[test]
  fn include_params() {
    let setup = mock_hmac_setup();
    let setup_hmac: &HmacSha1 = match &setup.factor_type {
      FactorType::HmacSha1(h) => h,
      _ => panic!(),
    };
    let setup_params = setup.factor_type.setup().params([0u8; 32].into()).unwrap();
    let mut hmac = mock_hmac_derive(&setup, &setup_params);

    let result = hmac.include_params(setup_params.clone());
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
    let setup_params = setup.factor_type.setup().params([0u8; 32].into()).unwrap();

    let mut hmac = mock_hmac_derive(&setup, &setup_params);
    hmac.include_params(setup_params).unwrap();

    let hmac_factor = match &hmac {
      FactorType::HmacSha1(h) => h,
      _ => panic!(),
    };

    let derive_params = hmac.params([0u8; 32].into()).unwrap();

    let challenge = hex::decode(derive_params.get("challenge").unwrap().as_str().unwrap()).unwrap();

    let pad = hex::decode(derive_params.get("pad").unwrap().as_str().unwrap()).unwrap();

    let response = crate::crypto::hmacsha1(&hmac_factor.padded_secret[..20], &challenge);
    let mut padded_key = [0u8; 32];
    padded_key[..response.len()].copy_from_slice(&response);

    let decrypted_secret = decrypt(pad, &padded_key);

    assert_eq!(decrypted_secret, hmac_factor.padded_secret);
  }

  #[test]
  fn output_derive_produces_correct_secret() {
    let setup = mock_hmac_setup();
    let setup_params = setup.factor_type.setup().params([0u8; 32].into()).unwrap();

    let mut derive_hmac = mock_hmac_derive(&setup, &setup_params);
    derive_hmac.include_params(setup_params).unwrap();

    let output = derive_hmac.derive().output();
    let secret = output["secret"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_u64().unwrap() as u8)
      .collect::<Vec<u8>>();

    let derive_hmac_factor = match &derive_hmac {
      FactorType::HmacSha1(h) => h,
      _ => panic!(),
    };

    assert_eq!(secret, derive_hmac_factor.padded_secret);
  }
}
