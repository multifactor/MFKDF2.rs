use std::collections::HashMap;

use uuid::Uuid;

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

#[tokio::test]
async fn test_key_derive() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_mfkdf2().await?;
  println!("Setup key: {}", key);

  let factor = ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour")?);

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors).await?;
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);

  Ok(())
}

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

#[tokio::test]
async fn test_key_derive_threshold() -> () {
  let key = mock_threshold_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  let factor =
    ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap());

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors).await.unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);

  let factor = ("password_2".to_string(), mfkdf2::derive::factors::password("hunter2").unwrap());

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors).await.unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
}

async fn mock_password_question_mfkdf2()
-> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![
    mfkdf2::setup::factors::password(
      "Tr0ubd4dour",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
    ),
    mfkdf2::setup::factors::question("Paris", mfkdf2::setup::factors::question::QuestionOptions {
      id:       Some("question_1".to_string()),
      question: "What is the capital of France?".to_string(),
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

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors).await.unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
}

async fn mock_uuid_mfkdf2()
-> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::uuid(
    Uuid::from_u128(123_456_789_012),
    mfkdf2::setup::factors::uuid::UUIDOptions { id: None },
  )]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;
  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn test_key_setup_uuid() -> () {
  let key = mock_uuid_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);
}

#[tokio::test]
async fn test_key_derive_uuid() -> () {
  let key = mock_uuid_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  let factor =
    ("uuid".to_string(), mfkdf2::derive::factors::uuid(Uuid::from_u128(123_456_789_012)).unwrap());

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors).await.unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
}

const HMACSHA1_SECRET: [u8; 20] = [
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14,
];

async fn mock_hmacsha1_mfkdf2()
-> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors =
    vec![mfkdf2::setup::factors::hmacsha1(mfkdf2::setup::factors::hmacsha1::HMACSHA1Options {
      id:     Some("hmacsha1_1".to_string()),
      secret: Some(HMACSHA1_SECRET),
    })]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, options).await?;
  Ok(key)
}

#[tokio::test]
async fn test_key_setup_hmacsha1() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_hmacsha1_mfkdf2().await?;
  println!("Setup key: {}", key);
  Ok(())
}

#[tokio::test]
async fn test_key_derive_hmacsha1() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_hmacsha1_mfkdf2().await?;
  println!("Setup key: {}", key);

  let challenge = key.policy.factors.iter().find(|f| f.kind == "hmacsha1").unwrap().params
    ["challenge"]
    .as_u64()
    .unwrap();

  let response = mfkdf2::crypto::hmacsha1(&HMACSHA1_SECRET, challenge);

  let factor = ("hmacsha1_1".to_string(), mfkdf2::derive::factors::hmacsha1(response).unwrap());
  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors).await?;
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
  Ok(())
}
