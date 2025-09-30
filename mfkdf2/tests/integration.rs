mod common;

use std::collections::HashMap;

use mfkdf2::setup::factors::hotp::OTPHash;
use rstest::rstest;

use crate::common::*;

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

#[tokio::test]
async fn key_derive_uuid() -> () {
  let key = mock_uuid_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  let factor = (
    "uuid".to_string(),
    mfkdf2::derive::factors::uuid(uuid::Uuid::from_u128(123_456_789_012)).unwrap(),
  );

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors, false, false).unwrap();

  assert_eq!(derived_key.key, key.key);
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
