use std::collections::HashMap;

async fn mock_mfkdf2() -> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
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
  mock_mfkdf2().await?;
  Ok(())
}

// #[tokio::test]
// async fn test_key_derive() -> Result<(), mfkdf2::error::MFKDF2Error> {
//   let key = mock_mfkdf2().await?;
//   println!("Setup key: {}", key);

//   let factor = ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour")?);

//   let factors = HashMap::from([factor]);

//   let derived_key = mfkdf2::derive::key(key.policy, factors).await?;
//   println!("Derived key: {}", derived_key);

//   assert_eq!(derived_key.key, key.key);

//   Ok(())
// }

#[tokio::test]
#[should_panic]
async fn test_key_derive_fail() -> () {
  let key = mock_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  let factor =
    ("password_1".to_string(), mfkdf2::derive::factors::password("wrong_password").unwrap());

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors).await.unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
}

async fn mock_threshold_mfkdf2()
-> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
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

// #[tokio::test]
// async fn test_key_derive_threshold() -> () {
//   let key = mock_threshold_mfkdf2().await.unwrap();
//   println!("Setup key: {}", key);

//   let factor =
//     ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap());

//   let factors = HashMap::from([factor]);

//   let derived_key = mfkdf2::derive::key(key.policy.clone(), factors).await.unwrap();
//   println!("Derived key: {}", derived_key);

//   assert_eq!(derived_key.key, key.key);

//   let factor = ("password_2".to_string(), mfkdf2::derive::factors::password("hunter2").unwrap());

//   let factors = HashMap::from([factor]);

//   let derived_key = mfkdf2::derive::key(key.policy, factors).await.unwrap();
//   println!("Derived key: {}", derived_key);

//   assert_eq!(derived_key.key, key.key);
// }

// async fn mock_password_question_mfkdf2()
// -> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
//   let factors = vec![
//     mfkdf2::setup::factors::password(
//       "Tr0ubd4dour",
//       mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
//     ),
//     mfkdf2::setup::factors::question("Paris", mfkdf2::setup::factors::question::QuestionOptions {
//       id:       Some("question_1".to_string()),
//       question: "What is the capital of France?".to_string(),
//     }),
//   ]
//   .into_iter()
//   .collect::<Result<Vec<_>, _>>()?;

//   let options = mfkdf2::setup::key::MFKDF2Options::default();
//   let key = mfkdf2::setup::key(factors, options).await?;
//   Ok(key)
// }

// #[tokio::test]
// async fn test_key_setup_password_question() -> () {
//   let key = mock_password_question_mfkdf2().await.unwrap();
//   println!("Setup key: {}", key);
// }

// #[tokio::test]
// async fn test_key_derive_password_question() -> () {
//   let key = mock_password_question_mfkdf2().await.unwrap();
//   println!("Setup key: {}", key);

//   let factor_password =
//     ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap());
//   let factor_question =
//     ("question_1".to_string(), mfkdf2::derive::factors::question("Paris").unwrap());

//   let factors = HashMap::from([factor_password, factor_question]);

//   let derived_key = mfkdf2::derive::key(key.policy.clone(), factors).await.unwrap();
//   println!("Derived key: {}", derived_key);

//   assert_eq!(derived_key.key, key.key);
// }

// async fn mock_uuid_mfkdf2()
// -> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
//   let factors = vec![mfkdf2::setup::factors::uuid(
//     Uuid::from_u128(123_456_789_012),
//     mfkdf2::setup::factors::uuid::UUIDOptions { id: None },
//   )]
//   .into_iter()
//   .collect::<Result<Vec<_>, _>>()?;
//   let options = mfkdf2::setup::key::MFKDF2Options::default();
//   let key = mfkdf2::setup::key(factors, options).await?;
//   Ok(key)
// }

// #[tokio::test]
// async fn test_key_setup_uuid() -> () {
//   let key = mock_uuid_mfkdf2().await.unwrap();
//   println!("Setup key: {}", key);
// }

// #[tokio::test]
// async fn test_key_derive_uuid() -> () {
//   let key = mock_uuid_mfkdf2().await.unwrap();
//   println!("Setup key: {}", key);

//   let factor =
//     ("uuid".to_string(),
// mfkdf2::derive::factors::uuid(Uuid::from_u128(123_456_789_012)).unwrap());

//   let factors = HashMap::from([factor]);

//   let derived_key = mfkdf2::derive::key(key.policy.clone(), factors).await.unwrap();
//   println!("Derived key: {}", derived_key);

//   assert_eq!(derived_key.key, key.key);
// }

// const HMACSHA1_SECRET: [u8; 20] = [
//   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
//   0x11, 0x12, 0x13, 0x14,
// ];

// async fn mock_hmacsha1_mfkdf2()
// -> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
//   let factors =
//     vec![mfkdf2::setup::factors::hmacsha1(mfkdf2::setup::factors::hmacsha1::HMACSHA1Options {
//       id:     Some("hmacsha1_1".to_string()),
//       secret: Some(HMACSHA1_SECRET),
//     })]
//     .into_iter()
//     .collect::<Result<Vec<_>, _>>()?;

//   let options = mfkdf2::setup::key::MFKDF2Options::default();
//   let key = mfkdf2::setup::key(factors, options).await?;
//   Ok(key)
// }

// #[tokio::test]
// async fn test_key_setup_hmacsha1() -> Result<(), mfkdf2::error::MFKDF2Error> {
//   let key = mock_hmacsha1_mfkdf2().await?;
//   println!("Setup key: {}", key);
//   Ok(())
// }

// #[tokio::test]
// async fn test_key_derive_hmacsha1() -> Result<(), mfkdf2::error::MFKDF2Error> {
//   let key = mock_hmacsha1_mfkdf2().await?;
//   println!("Setup key: {}", key);

//   let challenge = key.policy.factors.iter().find(|f| f.kind == "hmacsha1").unwrap().params
//     ["challenge"]
//     .as_u64()
//     .unwrap();

//   let response = mfkdf2::crypto::hmacsha1(&HMACSHA1_SECRET, challenge);

//   let factor = ("hmacsha1_1".to_string(), mfkdf2::derive::factors::hmacsha1(response).unwrap());
//   let factors = HashMap::from([factor]);

//   let derived_key = mfkdf2::derive::key(key.policy, factors).await?;
//   println!("Derived key: {}", derived_key);

//   assert_eq!(derived_key.key, key.key);
//   Ok(())
// }

// #[tokio::test]
// async fn test_policy_json_schema_compliance() {
//   let key = mock_mfkdf2().await.unwrap();

//   // Serialize the policy to JSON
//   let policy_json = serde_json::to_string_pretty(&key.policy).unwrap();
//   println!("Policy JSON:\n{}", policy_json);

//   // Parse it back to ensure it's valid JSON
//   let parsed: serde_json::Value = serde_json::from_str(&policy_json).unwrap();

//   // Check that all required schema fields are present
//   assert!(parsed.get("$schema").is_some(), "Missing $schema field");
//   assert!(parsed.get("$id").is_some(), "Missing $id field");
//   assert!(parsed.get("threshold").is_some(), "Missing threshold field");
//   assert!(parsed.get("salt").is_some(), "Missing salt field");
//   assert!(parsed.get("factors").is_some(), "Missing factors field");
//   assert!(parsed.get("hmac").is_some(), "Missing hmac field");

//   // Check schema URL
//   let schema = parsed.get("$schema").unwrap().as_str().unwrap();
//   assert_eq!(schema, "https://mfkdf.com/schema/v2.0.0/policy.json");

//   // Check factors array structure
//   let factors = parsed.get("factors").unwrap().as_array().unwrap();
//   assert!(!factors.is_empty(), "Factors array should not be empty");

//   let factor = &factors[0];
//   assert!(factor.get("id").is_some(), "Factor missing id field");
//   assert!(factor.get("type").is_some(), "Factor missing type field");
//   assert!(factor.get("pad").is_some(), "Factor missing pad field");
//   assert!(factor.get("salt").is_some(), "Factor missing salt field");
//   assert!(factor.get("secret").is_some(), "Factor missing secret field");
//   assert!(factor.get("params").is_some(), "Factor missing params field");

//   println!("✅ Policy JSON schema compliance test passed!");
// }

const HOTP_SECRET: [u8; 32] = [0u8; 32];

async fn mock_hotp_mfkdf2()
-> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
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

// #[tokio::test]
// async fn test_key_setup_hotp() -> Result<(), mfkdf2::error::MFKDF2Error> {
//   let key = mock_hotp_mfkdf2().await?;
//   println!("Setup key: {}", key);
//   Ok(())
// }

// #[tokio::test]
// async fn test_key_derive_hotp() -> Result<(), mfkdf2::error::MFKDF2Error> {
//   let key = mock_hotp_mfkdf2().await?;
//   println!("Setup key: {}", key);

//   // Extract HOTP parameters from the policy
//   let hotp_factor = key.policy.factors.iter().find(|f| f.kind == "hotp").unwrap();
//   let params: Value = serde_json::from_str(&hotp_factor.params).unwrap();
//   let counter = params["counter"].as_u64().unwrap();
//   dbg!(&params);
//   let digits = params["digits"].as_u64().unwrap() as u8;

//   // Generate the HOTP code that the user would need to provide
//   // This simulates what would come from an authenticator app
//   let generated_code = generate_hotp_code(&HOTP_SECRET, counter, digits);

//   println!("Generated HOTP code: {}", generated_code);

//   // Now use this code to derive the key
//   let factor = ("hotp_1".to_string(), mfkdf2::derive::factors::hotp(generated_code).unwrap());
//   let factors = HashMap::from([factor]);

//   let derived_key = mfkdf2::derive::key(key.policy, factors).await?;
//   println!("Derived key: {}", derived_key);

//   assert_eq!(derived_key.key, key.key);
//   Ok(())
// }

#[tokio::test]
#[should_panic]
async fn test_key_derive_hotp_wrong_code() {
  let key = mock_hotp_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  // Use a wrong HOTP code
  let wrong_code = 123_456_u32;
  let factor = ("hotp_1".to_string(), mfkdf2::derive::factors::hotp(wrong_code).unwrap());
  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors).await.unwrap();
  println!("Derived key: {}", derived_key);

  // This should fail because the wrong code will produce a different target
  assert_eq!(derived_key.key, key.key);
}

#[allow(dead_code)]
async fn mock_mixed_factors_mfkdf2()
-> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
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

// #[tokio::test]
// async fn test_key_derive_mixed_password_hotp() -> Result<(), mfkdf2::error::MFKDF2Error> {
//   let key = mock_mixed_factors_mfkdf2().await?;
//   println!("Setup key: {}", key);

//   // Extract HOTP parameters
//   let hotp_factor = key.policy.factors.iter().find(|f| f.kind == "hotp").unwrap();
//   let params: Value = serde_json::from_str(&hotp_factor.params).unwrap();
//   let counter = params["counter"].as_u64().unwrap();
//   let digits = params["digits"].as_u64().unwrap() as u8;

//   // Generate the correct HOTP code using SHA256 (different from previous test)
//   let generated_code = generate_hotp_code_sha256(&HOTP_SECRET, counter, digits);

//   println!("Generated HOTP code (SHA256): {}", generated_code);

//   // Create both factors
//   let factor_password =
//     ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap());
//   let factor_hotp = ("hotp_1".to_string(),
// mfkdf2::derive::factors::hotp(generated_code).unwrap());   let factors =
// HashMap::from([factor_password, factor_hotp]);

//   let derived_key = mfkdf2::derive::key(key.policy, factors).await?;
//   println!("Derived key: {}", derived_key);

//   assert_eq!(derived_key.key, key.key);
//   Ok(())
// }

// // Helper function for SHA256 HOTP codes
// fn generate_hotp_code_sha256(secret: &[u8], counter: u64, digits: u8) -> u32 {
//   use hmac::{Hmac, Mac};
//   use sha2::Sha256;

//   let counter_bytes = counter.to_be_bytes();
//   let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
//   mac.update(&counter_bytes);
//   let digest = mac.finalize().into_bytes();

//   // Dynamic truncation as per RFC 4226
//   let offset = (digest[digest.len() - 1] & 0xf) as usize;
//   let code = ((digest[offset] & 0x7f) as u32) << 24
//     | (digest[offset + 1] as u32) << 16
//     | (digest[offset + 2] as u32) << 8
//     | (digest[offset + 3] as u32);

//   code % (10_u32.pow(digits as u32))
// }
