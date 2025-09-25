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
async fn test_key_setup() -> Result<(), mfkdf2::error::MFKDF2Error> {
  mock_mfkdf2_password().await?;
  Ok(())
}

#[tokio::test]
async fn test_key_derive() -> Result<(), mfkdf2::error::MFKDF2Error> {
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
async fn test_key_derive_fail() -> () {
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
async fn test_key_setup_threshold() -> () { mock_threshold_mfkdf2().await.unwrap(); }

#[tokio::test]
async fn test_key_derive_threshold() -> () {
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
async fn test_key_setup_password_question() -> () {
  let key = mock_password_question_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);
}

#[tokio::test]
async fn test_key_derive_password_question() -> () {
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
async fn test_key_derive_uuid() -> () {
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
async fn test_key_derive_hmacsha1() -> Result<(), mfkdf2::error::MFKDF2Error> {
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
async fn test_policy_json_schema_compliance() {
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

async fn mock_threshold_factors_totp_mfkdf2() -> Result<MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error>
{
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
    mfkdf2::setup::factors::totp(mfkdf2::setup::factors::totp::TOTPOptions {
      id: Some("totp_1".to_string()),
      secret: Some(TOTP_SECRET.to_vec()),

      ..Default::default()
    }),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn key_derive_mixed_password_hotp_totp() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_threshold_factors_totp_mfkdf2().await?;
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

  // derive 1

  // Generate the correct HOTP code using SHA256
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

  // derive 2

  // Generate the correct TOTP code using SHA256
  let policy_totp_factor = derived_key.policy.factors.iter().find(|f| f.kind == "totp").unwrap();
  let totp_params: serde_json::Value = serde_json::from_str(&policy_totp_factor.params).unwrap();
  let time = totp_params["start"].as_u64().unwrap();
  let step = totp_params["step"].as_u64().unwrap();
  let hash = match totp_params["hash"].as_str().unwrap() {
    "sha1" => OTPHash::Sha1,
    "sha256" => OTPHash::Sha256,
    "sha512" => OTPHash::Sha512,
    _ => panic!("unknown hash algrorithm"),
  };
  let digits = totp_params["digits"].as_u64().unwrap() as u8;
  let counter = time / (step * 1000);

  let totp_code =
    mfkdf2::setup::factors::hotp::generate_hotp_code(&TOTP_SECRET, counter, &hash, digits);

  // Create both factors
  let factor_password =
    ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap());
  let factor_totp = ("totp_1".to_string(), mfkdf2::derive::factors::totp(totp_code, None).unwrap());
  let factors = HashMap::from([factor_password, factor_totp]);

  let derived_key_2 = mfkdf2::derive::key(derived_key.policy, factors, false, false)?;
  println!("Derived key: {}", derived_key_2);

  assert_eq!(derived_key_2.key, derived_key.key);

  Ok(())
}
