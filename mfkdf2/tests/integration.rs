use std::collections::HashMap;

use mfkdf2::{definitions::mfkdf_derived_key::MFKDF2DerivedKey, setup::factors::hotp::OTPHash};

async fn mock_mfkdf2_password() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::password(
    "Tr0ubd4dour",
    mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
  )]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn key_setup() -> Result<(), mfkdf2::error::MFKDF2Error> {
  mock_mfkdf2_password().await?;
  Ok(())
}

#[tokio::test]
async fn key_derive() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_mfkdf2_password().await?;
  println!("Setup key: {}", key);

  let factor = ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour")?);

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors, false, false)?;
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);

  Ok(())
}

#[tokio::test]
#[should_panic]
async fn key_derive_fail() -> () {
  let key = mock_mfkdf2_password().await.unwrap();
  println!("Setup key: {}", key);

  let factor =
    ("password_1".to_string(), mfkdf2::derive::factors::password("wrong_password").unwrap());

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors, false, false).unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
}

async fn mock_threshold_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
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
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn key_setup_threshold() -> () { mock_threshold_mfkdf2().await.unwrap(); }

#[tokio::test]
async fn key_derive_threshold() -> () {
  let key = mock_threshold_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  let factor =
    ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap());

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors, false, false).unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);

  let factor = ("password_2".to_string(), mfkdf2::derive::factors::password("hunter2").unwrap());

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors, false, false).unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
}

async fn mock_password_question_mfkdf2()
-> Result<mfkdf2::definitions::mfkdf_derived_key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
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
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn key_setup_password_question() -> () {
  let key = mock_password_question_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);
}

#[tokio::test]
async fn key_derive_password_question() -> () {
  let key = mock_password_question_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  let factor_password =
    ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap());
  let factor_question =
    ("question_1".to_string(), mfkdf2::derive::factors::question("Paris").unwrap());

  let factors = HashMap::from([factor_password, factor_question]);

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors, false, false).unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
}

async fn mock_uuid_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::uuid(mfkdf2::setup::factors::uuid::UUIDOptions {
    id:   None,
    uuid: Some(uuid::Uuid::from_u128(123_456_789_012).to_string()),
  })]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;
  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn key_derive_uuid() -> () {
  let key = mock_uuid_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  let factor = (
    "uuid".to_string(),
    mfkdf2::derive::factors::uuid(uuid::Uuid::from_u128(123_456_789_012).to_string()).unwrap(),
  );

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors, false, false).unwrap();

  assert_eq!(derived_key.key, key.key);
}

const HMACSHA1_SECRET: [u8; 20] = [
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14,
];

async fn mock_hmacsha1_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors =
    vec![mfkdf2::setup::factors::hmacsha1(mfkdf2::setup::factors::hmacsha1::HmacSha1Options {
      id:     Some("hmacsha1_1".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    })]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn key_derive_hmacsha1() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_hmacsha1_mfkdf2().await?;
  println!("Setup key: {}", key);

  let challenge = hex::decode(
    serde_json::from_str::<serde_json::Value>(
      key.policy.factors.iter().find(|f| f.kind == "hmacsha1").unwrap().params.as_str(),
    )
    .unwrap()["challenge"]
      .as_str()
      .unwrap(),
  )
  .unwrap();

  let response = mfkdf2::crypto::hmacsha1(&HMACSHA1_SECRET, &challenge);

  let factor =
    ("hmacsha1_1".to_string(), mfkdf2::derive::factors::hmacsha1(response.into()).unwrap());
  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors, false, false)?;
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
  Ok(())
}

#[tokio::test]
async fn policy_json_schema_compliance() {
  let key = mock_mfkdf2_password().await.unwrap();

  // Serialize the policy to JSON
  let policy_json = serde_json::to_string_pretty(&key.policy).unwrap();
  println!("Policy JSON:\n{}", policy_json);

  // Parse it back to ensure it's valid JSON
  let parsed: serde_json::Value = serde_json::from_str(&policy_json).unwrap();

  // Check that all required schema fields are present
  assert!(parsed.get("$schema").is_some(), "Missing $schema field");
  assert!(parsed.get("$id").is_some(), "Missing $id field");
  assert!(parsed.get("threshold").is_some(), "Missing threshold field");
  assert!(parsed.get("salt").is_some(), "Missing salt field");
  assert!(parsed.get("factors").is_some(), "Missing factors field");
  assert!(parsed.get("hmac").is_some(), "Missing hmac field");

  // Check schema URL
  let schema = parsed.get("$schema").unwrap().as_str().unwrap();
  assert_eq!(schema, "https://mfkdf.com/schema/v2.0.0/policy.json");

  // Check factors array structure
  let factors = parsed.get("factors").unwrap().as_array().unwrap();
  assert!(!factors.is_empty(), "Factors array should not be empty");

  let factor = &factors[0];
  assert!(factor.get("id").is_some(), "Factor missing id field");
  assert!(factor.get("type").is_some(), "Factor missing type field");
  assert!(factor.get("pad").is_some(), "Factor missing pad field");
  assert!(factor.get("salt").is_some(), "Factor missing salt field");
  assert!(factor.get("secret").is_some(), "Factor missing secret field");
  assert!(factor.get("params").is_some(), "Factor missing params field");

  println!("✅ Policy JSON schema compliance test passed!");
}

const HOTP_SECRET: [u8; 20] = [0u8; 20];
const TOTP_SECRET: [u8; 20] = [0u8; 20];
const PASSKEY_SECRET: [u8; 32] = [7; 32];
const TEST_JWK: &str = r#"{
    "key_ops": ["encrypt", "decrypt"],
    "ext": true,
    "alg": "RSA-OAEP-256",
    "kty": "RSA",
    "n": "1jR1L4H7Wov2W3XWlw1OII-fh_YuzfbZgpMCeSIPUd5oPvyvRf8nshkclQ9EQy6QlCZPX0HzCqkGokppxirKisyjfAlremiL8H60t2aapN_T3eClJ3KUxyEO1cejWoKejD86OtL_DWc04odInpcRmFgAF8mgjbEZRD0oSzaGlr70Ezi8p0yhpMTFM2Ltn0LG6SJ2_LGQwpEFNFf7790IoNpx8vKIZq0Ok1dGhC808f2t0ZhVFmxYnR-fp1jxd5B9nYDkjyJbWQK4vPlpAOgHw9v8G2Cg2X1TX2Ywr19tB249es2NlOYrFRQugzPyKfuVYxpFgoJfMuP83SPx-RvK6w",
    "e": "AQAB"
  }"#;

async fn mock_hotp_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
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
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn key_setup_hotp() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_hotp_mfkdf2().await?;
  println!("Setup key: {}", key);
  Ok(())
}

#[tokio::test]
async fn key_derive_hotp() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_hotp_mfkdf2().await?;
  println!("Setup key: {}", key);

  // Extract HOTP parameters from the policy
  let hotp_factor = key.policy.factors.iter().find(|f| f.kind == "hotp").unwrap();
  let params: serde_json::Value = serde_json::from_str(&hotp_factor.params).unwrap();
  let counter = params["counter"].as_u64().unwrap();
  let digits = params["digits"].as_u64().unwrap() as u8;
  let hash = match params["hash"].as_str().unwrap() {
    "sha1" => OTPHash::Sha1,
    "sha256" => OTPHash::Sha256,
    "sha512" => OTPHash::Sha512,
    _ => panic!("unknown hash algrorithm"),
  };

  // Generate the HOTP code that the user would need to provide
  // This simulates what would come from an authenticator app
  let generated_code =
    mfkdf2::setup::factors::hotp::generate_hotp_code(&HOTP_SECRET, counter, &hash, digits);

  println!("Generated HOTP code: {}", generated_code);

  // Now use this code to derive the key
  let factor = ("hotp_1".to_string(), mfkdf2::derive::factors::hotp(generated_code).unwrap());
  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors, false, false)?;
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
  Ok(())
}

#[tokio::test]
#[should_panic]
async fn key_derive_hotp_wrong_code() {
  let key = mock_hotp_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  // Use a wrong HOTP code
  let wrong_code = 123_456_u32;
  let factor = ("hotp_1".to_string(), mfkdf2::derive::factors::hotp(wrong_code).unwrap());
  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors, false, false).unwrap();
  println!("Derived key: {}", derived_key);

  // This should fail because the wrong code will produce a different target
  assert_eq!(derived_key.key, key.key);
}

async fn mock_mixed_factors_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
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
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn key_derive_mixed_password_hotp() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_mixed_factors_mfkdf2().await?;
  println!("Setup key: {}", key);

  // Extract HOTP parameters
  let hotp_factor = key.policy.factors.iter().find(|f| f.kind == "hotp").unwrap();
  let params: serde_json::Value = serde_json::from_str(&hotp_factor.params).unwrap();
  let counter = params["counter"].as_u64().unwrap();
  let digits = params["digits"].as_u64().unwrap() as u8;
  let hash = match params["hash"].as_str().unwrap() {
    "sha1" => OTPHash::Sha1,
    "sha256" => OTPHash::Sha256,
    "sha512" => OTPHash::Sha512,
    _ => panic!("unknown hash algrorithm"),
  };

  // Generate the correct HOTP code using SHA256 (different from previous test)
  let generated_code =
    mfkdf2::setup::factors::hotp::generate_hotp_code(&HOTP_SECRET, counter, &hash, digits);

  println!("Generated HOTP code (SHA256): {}", generated_code);

  // Create both factors
  let factor_password =
    ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap());
  let factor_hotp = ("hotp_1".to_string(), mfkdf2::derive::factors::hotp(generated_code).unwrap());
  let factors = HashMap::from([factor_password, factor_hotp]);

  let derived_key = mfkdf2::derive::key(key.policy, factors, false, false)?;
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
  Ok(())
}

use rstest::rstest;

fn create_setup_factor(name: &str) -> mfkdf2::setup::factors::MFKDF2Factor {
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
      uuid: Some("f9bf78b9-54e7-4696-97dc-5e750de4c592".to_string()),
    })
    .unwrap(),
    "ooba" => mfkdf2::setup::factors::ooba::ooba(mfkdf2::setup::factors::ooba::OobaOptions {
      id:     Some("ooba_1".to_string()),
      length: 8,
      key:    Some(TEST_JWK.to_string()),
      params: Some(r#"{"foo":"bar"}"#.to_string()),
    })
    .unwrap(),
    "passkey" => mfkdf2::setup::factors::passkey::passkey(
      PASSKEY_SECRET.to_vec(),
      mfkdf2::setup::factors::passkey::PasskeyOptions { id: Some("passkey_1".to_string()) },
    )
    .unwrap(),
    _ => panic!("Unknown factor type for setup: {}", name),
  }
}

pub fn create_derive_factor(
  name: &str,
  policy: &mfkdf2::policy::Policy,
) -> (String, mfkdf2::setup::factors::MFKDF2Factor) {
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
      let time = params["start"].as_u64().unwrap();
      let step = params["step"].as_u64().unwrap();
      let hash = serde_json::from_value(params["hash"].clone()).unwrap();
      let digits = params["digits"].as_u64().unwrap() as u8;
      let counter = time / (step * 1000);

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
      mfkdf2::derive::factors::uuid("f9bf78b9-54e7-4696-97dc-5e750de4c592".to_string()).unwrap(),
    ),
    "ooba" => {
      let factor_policy = policy.factors.iter().find(|f| f.id == "ooba_1").unwrap();
      let params: serde_json::Value = serde_json::from_str(&factor_policy.params).unwrap();
      let code = params["params"]["code"].as_str().unwrap();
      ("ooba_1".to_string(), mfkdf2::derive::factors::ooba(code.to_string()).unwrap())
    },
    "passkey" => (
      "passkey_1".to_string(),
      mfkdf2::derive::factors::passkey::passkey(PASSKEY_SECRET.to_vec()).unwrap(),
    ),
    _ => panic!("Unknown factor type for derive: {}", name),
  }
}

#[rstest]
#[case(vec!["password", "hotp", "totp"], 2, vec![vec!["password", "hotp"], vec!["password", "totp"]], 1)]
#[case(vec!["password", "hotp", "totp"], 3, vec![vec!["password", "hotp", "totp"]], 1)]
#[case(vec!["password", "hotp", "totp", "hmacsha1"], 3, vec![vec!["password", "hotp", "totp"], vec!["password", "hotp", "hmacsha1"]], 1)]
#[case(vec!["question", "uuid"], 2, vec![vec!["question", "uuid"]], 1)]
#[case(vec!["ooba", "passkey", "password"], 2, vec![vec!["ooba", "passkey"], vec!["password", "passkey"]], 1)]
#[case(vec!["password", "hotp"], 2, vec![vec!["password", "hotp"]], 3)]
#[tokio::test]
async fn key_derivation_combinations(
  #[case] setup_factor_names: Vec<&str>,
  #[case] threshold: u8,
  #[case] derive_combinations: Vec<Vec<&str>>,
  #[case] derivation_runs: u32,
) -> Result<(), mfkdf2::error::MFKDF2Error> {
  // 1. Setup key
  let setup_factors: Vec<_> = setup_factor_names.into_iter().map(create_setup_factor).collect();

  let options =
    mfkdf2::setup::key::MFKDF2Options { threshold: Some(threshold), ..Default::default() };
  let setup_key = mfkdf2::setup::key(setup_factors, options).await?;

  // 2. Loop through derivation combinations
  for combo in derive_combinations {
    let mut policy_for_run = setup_key.policy.clone();
    for i in 0..derivation_runs {
      let derive_factors: HashMap<_, _> =
        combo.iter().map(|name| create_derive_factor(name, &policy_for_run)).collect();

      let derived_key = mfkdf2::derive::key(policy_for_run.clone(), derive_factors, false, false)?;

      assert_eq!(
        derived_key.key, setup_key.key,
        "Failed for combination: {:?}, iteration: {}",
        combo, i
      );

      policy_for_run = derived_key.policy;
    }
  }

  Ok(())
}
