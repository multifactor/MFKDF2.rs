#![allow(deprecated)]
#![allow(dead_code)]

use mfkdf2::{
  definitions::MFKDF2DerivedKey,
  setup::{Derive, Setup},
};

pub const HMACSHA1_SECRET: [u8; 20] = [
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14,
];
pub const HOTP_SECRET: [u8; 20] = [0u8; 20];
pub const TOTP_SECRET: [u8; 20] = [0u8; 20];
pub const PASSKEY_SECRET: [u8; 32] = [7; 32];
pub const TEST_JWK: &str = r#"{
    "key_ops": ["encrypt", "decrypt"],
    "ext": true,
    "alg": "RSA-OAEP-256",
    "kty": "RSA",
    "n": "1jR1L4H7Wov2W3XWlw1OII-fh_YuzfbZgpMCeSIPUd5oPvyvRf8nshkclQ9EQy6QlCZPX0HzCqkGokppxirKisyjfAlremiL8H60t2aapN_T3eClJ3KUxyEO1cejWoKejD86OtL_DWc04odInpcRmFgAF8mgjbEZRD0oSzaGlr70Ezi8p0yhpMTFM2Ltn0LG6SJ2_LGQwpEFNFf7790IoNpx8vKIZq0Ok1dGhC808f2t0ZhVFmxYnR-fp1jxd5B9nYDkjyJbWQK4vPlpAOgHw9v8G2Cg2X1TX2Ywr19tB249es2NlOYrFRQugzPyKfuVYxpFgoJfMuP83SPx-RvK6w",
    "e": "AQAB"
  }"#;

pub fn mock_mfkdf2_password() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::password(
    "Tr0ubd4dour",
    mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
  )]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options)?;
  Ok(key)
}

pub fn mock_threshold_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![
    mfkdf2::setup::factors::password(
      "Tr0ubd4dour",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
    ),
    mfkdf2::setup::factors::password(
      "hunter2",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_2".to_string()) },
    ),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options { threshold: Some(1), ..Default::default() };
  let key = mfkdf2::setup::key(factors, options)?;
  Ok(key)
}

pub fn mock_password_question_mfkdf2()
-> Result<mfkdf2::definitions::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![
    mfkdf2::setup::factors::password(
      "Tr0ubd4dour",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
    ),
    mfkdf2::setup::factors::question("Paris", mfkdf2::setup::factors::question::QuestionOptions {
      id:       Some("question_1".to_string()),
      question: Some("What is the capital of France?".to_string()),
    }),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options)?;
  Ok(key)
}

pub fn mock_uuid_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::uuid(mfkdf2::setup::factors::uuid::UUIDOptions {
    id:   None,
    uuid: Some(uuid::Uuid::from_u128(123_456_789_012)),
  })]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;
  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options)?;
  Ok(key)
}

pub fn mock_hmacsha1_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors =
    vec![mfkdf2::setup::factors::hmacsha1(mfkdf2::setup::factors::hmacsha1::HmacSha1Options {
      id:     Some("hmacsha1_1".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    })]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options)?;
  Ok(key)
}

pub fn mock_hotp_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::hotp(mfkdf2::setup::factors::hotp::HOTPOptions {
    id:     Some("hotp_1".to_string()),
    secret: Some(HOTP_SECRET.to_vec()),
    digits: 6,
    hash:   mfkdf2::setup::factors::hotp::OTPHash::Sha1,
    issuer: "MFKDF".to_string(),
    label:  "test".to_string(),
  })]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options)?;
  Ok(key)
}

pub fn mock_mixed_factors_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![
    mfkdf2::setup::factors::password(
      "Tr0ubd4dour",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
    ),
    mfkdf2::setup::factors::hotp(mfkdf2::setup::factors::hotp::HOTPOptions {
      id:     Some("hotp_1".to_string()),
      secret: Some(HOTP_SECRET.to_vec()),
      digits: 6,
      hash:   mfkdf2::setup::factors::hotp::OTPHash::Sha256,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    }),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options)?;
  Ok(key)
}

pub fn create_setup_factor(name: &str) -> mfkdf2::definitions::MFKDF2Factor<Setup> {
  match name {
    "password" => mfkdf2::setup::factors::password(
      "Tr0ubd4dour",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
    )
    .unwrap(),
    "hotp" => mfkdf2::setup::factors::hotp(mfkdf2::setup::factors::hotp::HOTPOptions {
      id:     Some("hotp_1".to_string()),
      secret: Some(HOTP_SECRET.to_vec()),
      digits: 6,
      hash:   mfkdf2::setup::factors::hotp::OTPHash::Sha256,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    })
    .unwrap(),
    "totp" => mfkdf2::setup::factors::totp(mfkdf2::setup::factors::totp::TOTPOptions {
      id: Some("totp_1".to_string()),
      secret: Some(TOTP_SECRET.to_vec()),
      ..Default::default()
    })
    .unwrap(),
    "hmacsha1" =>
      mfkdf2::setup::factors::hmacsha1(mfkdf2::setup::factors::hmacsha1::HmacSha1Options {
        id:     Some("hmacsha1_1".to_string()),
        secret: Some(HMACSHA1_SECRET.to_vec()),
      })
      .unwrap(),
    "question" => mfkdf2::setup::factors::question::question(
      "my secret answer",
      mfkdf2::setup::factors::question::QuestionOptions {
        id:       Some("question_1".to_string()),
        question: Some("What is my secret?".to_string()),
      },
    )
    .unwrap(),
    "uuid" => mfkdf2::setup::factors::uuid::uuid(mfkdf2::setup::factors::uuid::UUIDOptions {
      id:   Some("uuid_1".to_string()),
      uuid: Some(uuid::Uuid::parse_str("f9bf78b9-54e7-4696-97dc-5e750de4c592").unwrap()),
    })
    .unwrap(),
    "ooba" => mfkdf2::setup::factors::ooba::ooba(mfkdf2::setup::factors::ooba::OobaOptions {
      id:     Some("ooba_1".to_string()),
      length: Some(8),
      key:    Some(TEST_JWK.to_string()),
      params: Some(r#"{"foo":"bar"}"#.to_string()),
    })
    .unwrap(),
    "passkey" => mfkdf2::setup::factors::passkey::passkey(
      PASSKEY_SECRET,
      mfkdf2::setup::factors::passkey::PasskeyOptions { id: Some("passkey_1".to_string()) },
    )
    .unwrap(),
    _ => panic!("Unknown factor type for setup: {}", name),
  }
}
pub fn create_derive_factor(
  name: &str,
  policy: &mfkdf2::policy::Policy,
) -> (String, mfkdf2::definitions::MFKDF2Factor<Derive>) {
  match name {
    "password" =>
      ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap()),
    "hotp" => {
      let factor_policy = policy.factors.iter().find(|f| f.id == "hotp_1").unwrap();
      let params: serde_json::Value = serde_json::from_str(&factor_policy.params).unwrap();
      let counter = params["counter"].as_u64().unwrap();
      let digits = params["digits"].as_u64().unwrap() as u8;
      let hash = serde_json::from_value(params["hash"].clone()).unwrap();

      let generated_code =
        mfkdf2::setup::factors::hotp::generate_hotp_code(&HOTP_SECRET, counter, &hash, digits);
      ("hotp_1".to_string(), mfkdf2::derive::factors::hotp(generated_code).unwrap())
    },
    "totp" => {
      let factor_policy = policy.factors.iter().find(|f| f.id == "totp_1").unwrap();
      let params: serde_json::Value = serde_json::from_str(&factor_policy.params).unwrap();
      let time =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
      let step = params["step"].as_u64().unwrap();
      let hash = serde_json::from_value(params["hash"].clone()).unwrap();
      let digits = params["digits"].as_u64().unwrap() as u8;
      let counter = time as u64 / (step * 1000);

      let totp_code =
        mfkdf2::setup::factors::hotp::generate_hotp_code(&TOTP_SECRET, counter, &hash, digits);
      ("totp_1".to_string(), mfkdf2::derive::factors::totp(totp_code, None).unwrap())
    },
    "hmacsha1" => {
      let factor_policy = policy.factors.iter().find(|f| f.id == "hmacsha1_1").unwrap();
      let params: serde_json::Value = serde_json::from_str(&factor_policy.params).unwrap();
      let challenge = hex::decode(params["challenge"].as_str().unwrap()).unwrap();
      let response = mfkdf2::crypto::hmacsha1(&HMACSHA1_SECRET, &challenge);
      ("hmacsha1_1".to_string(), mfkdf2::derive::factors::hmacsha1(response.into()).unwrap())
    },
    "question" =>
      ("question_1".to_string(), mfkdf2::derive::factors::question("my secret answer").unwrap()),
    "uuid" => (
      "uuid_1".to_string(),
      mfkdf2::derive::factors::uuid(
        uuid::Uuid::parse_str("f9bf78b9-54e7-4696-97dc-5e750de4c592").unwrap(),
      )
      .unwrap(),
    ),
    "ooba" => {
      let factor_policy = policy.factors.iter().find(|f| f.id == "ooba_1").unwrap();
      let params: serde_json::Value = serde_json::from_str(&factor_policy.params).unwrap();
      let code = params["params"]["code"].as_str().unwrap();
      ("ooba_1".to_string(), mfkdf2::derive::factors::ooba(code.to_string()).unwrap())
    },
    "passkey" =>
      ("passkey_1".to_string(), mfkdf2::derive::factors::passkey::passkey(PASSKEY_SECRET).unwrap()),
    _ => panic!("Unknown factor type for derive: {}", name),
  }
}
