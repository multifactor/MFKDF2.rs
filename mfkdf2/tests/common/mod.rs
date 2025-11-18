#![allow(dead_code)]

use base64::Engine;
use mfkdf2::definitions::MFKDF2DerivedKey;
use rsa::{
  RsaPrivateKey, RsaPublicKey,
  pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
  traits::PublicKeyParts,
};

pub const HMACSHA1_SECRET: [u8; 20] = [
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14,
];
pub const HOTP_SECRET: [u8; 20] = [0u8; 20];
pub const TOTP_SECRET: [u8; 20] = [0u8; 20];
pub const PASSKEY_SECRET: [u8; 32] = [7; 32];
pub const RSA_PUBLIC_KEY: &str = r#"3082010a0282010100bc2275550f8c1a80bad27476c18cb4e2906c686468cccd42318bede7bbdbaf3c0da4d799586ee1ceebe30c08bb1a9dbd09bad68faaa4082e2d9f76a295caf4571f96058fdc0e3ccaa88cd6037fb7e74a6afae9fff3c43f4a0c8e9f8f22294df6d77969744092c54a15039e6d71862ac9702205afbff48b3b3f7046cfbff2938f202d00060979a6c1822c309ef7bd008812f729d2b5c6f3d79f4b316e712811aebade3320b1f28901acab225c64c51ad0c4c1dc93a254a636afddaf2c6a9e8d8114fb24f7a716c58030e9bae040e044a1f47d921c0a3e157389da1891f1b72a9e27896ecc4981a09eafa0a71f00a7c72b1fc7c98659eaf9576dc295aaaf0866c10203010001"#;
pub const RSA_PRIVATE_KEY: &str = r#"308204a40201000282010100bc2275550f8c1a80bad27476c18cb4e2906c686468cccd42318bede7bbdbaf3c0da4d799586ee1ceebe30c08bb1a9dbd09bad68faaa4082e2d9f76a295caf4571f96058fdc0e3ccaa88cd6037fb7e74a6afae9fff3c43f4a0c8e9f8f22294df6d77969744092c54a15039e6d71862ac9702205afbff48b3b3f7046cfbff2938f202d00060979a6c1822c309ef7bd008812f729d2b5c6f3d79f4b316e712811aebade3320b1f28901acab225c64c51ad0c4c1dc93a254a636afddaf2c6a9e8d8114fb24f7a716c58030e9bae040e044a1f47d921c0a3e157389da1891f1b72a9e27896ecc4981a09eafa0a71f00a7c72b1fc7c98659eaf9576dc295aaaf0866c10203010001028201005191e32b893d26b48fcbf5e113942d4d5a6f16680aa4598e8caaedf09e9be683742af7abae130d66c911bd42ffd4cf758a056f4805256fc28dd768f99f56cad0078ae5487591dabbc78ea0b00dad2fe42d343346dd6b464195e634ba3b868b1e2e589ee75fa40354567e262faf9c0b6b216a2eeaffa048c9dc7c92c73aa33364898898cd981df9929c6ce50b17effb7e27909e8d775c290639a625dce01e3a6f1cda2a55de1c0ace5e8eaf63e416243c12cbc68fc09554f7a3b7bb92ec1fe5a426de06b855004f61e1f84029430b7c04794d1cf8b480a274b9e8db1288203563b8547fe9141637ac3c8246b0847b7aa942e8d55bb9a11fc38924df403fadf03d02818100e4a543f316bbdc75c56d24f4a7ee6c4713e998d56eeda52402e42fb63cb1324ab856be40b16c3a903a86a7b78003c51e84e53af9d3b7e4b2da44b8482b33eec3e3d98e1cf29d07a496442d2e0f0712b276eb8420e41d625d4641379dbb4d7ac2ece58b72d12810155ff1abc4597ba9e6f2a02c925a0fd1b0bce62f16bc977fd702818100d2a4765dfcd3a1b1cdd07bc01b00aac6a62d93502096f0f711142b9cda50eb9cfdc50ae8324f9c8f2eb06e30232e37f45e5e6849a8a7c05811e4c1db5718390f30b278d2b06effc26241911b222caa78bea60b39d0440b241023c1f5588f7e93744c42dec35bdd383c156837357297cdf36c1044788990196ceafe03bc41db2702818100ba2354db0c51e9db32db74ef7bdb1ce90c6bea912f1a668b9792fec8a44639441d27f9009fb015491f6c4a139832f981abfd15f3168a29b3f4ff66ead1c91882fef638bc9642825b5a3dac6e47aba16c0a66178dd3479cb184a5494aae9617efa27e08f57312e36d134ba26359d9d3ea80f126f80a3bc0a0da57a654233a4ec7028180246651220ab79380833d5cb524b567cd6e180015df9bd5c60c087d44dca111260ee046f33b0670da7949f9b08dd3c5cd8fa526c65bc3a9444ecb46089e334c60e89c5eaea1d87c8fdda4d0eb6c6b6585fa03fd7a9f17b3092754d6868c2837ca49558854b053a695ba2444df0d7860ed30fc628f42791b1299b4bdf26d4cc00f02818100e0b13a82d6941af546f0b9838c384cc3c121bd12f6313ac5605d7b77cf5b651239eb3d90316999619cbedcc84014a447104082134de086fce9a9cc813c3dfe2b47a1b424dd646890909ad7a987a8577e5256892dc1d186ad20971223cac0881349fc4fe4cfbd6421a49fa5ec1abe52f6faad264f8d93c65be84c753287241fc7"#;

fn keypair() -> (RsaPrivateKey, RsaPublicKey) {
  let bits = 2048;
  let private_key =
    RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).expect("failed to generate a key");
  let public_key = RsaPublicKey::from(&private_key);
  (private_key, public_key)
}

fn jwk(key: &RsaPublicKey) -> jsonwebtoken::jwk::Jwk {
  let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
  let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
  let jwk = serde_json::json!({
    "key_ops": ["encrypt", "decrypt"],
    "ext": true,
    "alg": "RSA-OAEP-256",
    "kty": "RSA",
    "n": n,
    "e": e,
  });
  serde_json::from_value(jwk).unwrap()
}

pub fn mock_mfkdf2_password() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::password(
    "Tr0ubd4dour",
    mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
  )]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(&factors, options)?;
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
  let key = mfkdf2::setup::key(&factors, options)?;
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
  let key = mfkdf2::setup::key(&factors, options)?;
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
  let key = mfkdf2::setup::key(&factors, options)?;
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
  let key = mfkdf2::setup::key(&factors, options)?;
  Ok(key)
}

pub fn mock_hotp_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::hotp(mfkdf2::setup::factors::hotp::HOTPOptions {
    id: Some("hotp_1".to_string()),
    secret: Some(HOTP_SECRET.to_vec()),
    ..Default::default()
  })]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(&factors, options)?;
  Ok(key)
}

pub fn mock_mixed_factors_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![
    mfkdf2::setup::factors::password(
      "Tr0ubd4dour",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
    ),
    mfkdf2::setup::factors::hotp(mfkdf2::setup::factors::hotp::HOTPOptions {
      id: Some("hotp_1".to_string()),
      secret: Some(HOTP_SECRET.to_vec()),
      ..Default::default()
    }),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(&factors, options)?;
  Ok(key)
}

pub fn create_setup_factor(name: &str) -> mfkdf2::definitions::MFKDF2Factor {
  match name {
    "password" => mfkdf2::setup::factors::password(
      "Tr0ubd4dour",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
    )
    .unwrap(),
    "hotp" => mfkdf2::setup::factors::hotp(mfkdf2::setup::factors::hotp::HOTPOptions {
      id: Some("hotp_1".to_string()),
      secret: Some(HOTP_SECRET.to_vec()),
      ..Default::default()
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
    "ooba" => {
      let rsa_public_key =
        RsaPublicKey::from_pkcs1_der(&hex::decode(RSA_PUBLIC_KEY).unwrap()).unwrap();
      let test_jwk = jwk(&rsa_public_key);
      mfkdf2::setup::factors::ooba::ooba(mfkdf2::setup::factors::ooba::OobaOptions {
        id:     Some("ooba_1".to_string()),
        length: Some(8),
        key:    Some(test_jwk),
        params: Some(serde_json::json!({"foo":"bar"})),
      })
      .unwrap()
    },
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
) -> (String, mfkdf2::definitions::MFKDF2Factor) {
  match name {
    "password" =>
      ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap()),
    "hotp" => {
      let factor_policy = policy.factors.iter().find(|f| f.id == "hotp_1").unwrap();
      let params = &factor_policy.params;
      let counter = params["counter"].as_u64().unwrap();
      let digits = params["digits"].as_u64().unwrap() as u32;
      let hash = serde_json::from_value(params["hash"].clone()).unwrap();

      let generated_code =
        mfkdf2::otpauth::generate_hotp_code(&HOTP_SECRET, counter, &hash, digits);
      ("hotp_1".to_string(), mfkdf2::derive::factors::hotp(generated_code).unwrap())
    },
    "totp" => {
      let factor_policy = policy.factors.iter().find(|f| f.id == "totp_1").unwrap();
      let params = &factor_policy.params;
      let time =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
      let step = params["step"].as_u64().unwrap();
      let hash = serde_json::from_value(params["hash"].clone()).unwrap();
      let digits = params["digits"].as_u64().unwrap() as u32;
      let counter = time as u64 / (step * 1000);

      let totp_code = mfkdf2::otpauth::generate_hotp_code(&TOTP_SECRET, counter, &hash, digits);
      ("totp_1".to_string(), mfkdf2::derive::factors::totp(totp_code, None).unwrap())
    },
    "hmacsha1" => {
      let factor_policy = policy.factors.iter().find(|f| f.id == "hmacsha1_1").unwrap();
      let params = &factor_policy.params;
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
      let rsa_private_key =
        RsaPrivateKey::from_pkcs1_der(&hex::decode(RSA_PRIVATE_KEY).unwrap()).unwrap();

      let factor_policy = policy.factors.iter().find(|f| f.id == "ooba_1").unwrap();
      let params = &factor_policy.params;
      let ciphertext = hex::decode(params["next"].as_str().unwrap()).unwrap();
      let decrypted = serde_json::from_slice::<serde_json::Value>(
        &rsa_private_key.decrypt(rsa::Oaep::new::<sha2::Sha256>(), &ciphertext).unwrap(),
      )
      .unwrap();
      let code = decrypted["code"].as_str().unwrap();

      ("ooba_1".to_string(), mfkdf2::derive::factors::ooba(code).unwrap())
    },
    "passkey" =>
      ("passkey_1".to_string(), mfkdf2::derive::factors::passkey::passkey(PASSKEY_SECRET).unwrap()),
    _ => panic!("Unknown factor type for derive: {}", name),
  }
}
