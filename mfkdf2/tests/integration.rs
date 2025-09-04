use std::collections::HashMap;

async fn mock_mfkdf2() -> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::password(
    "Tr0ubd4dour",
    Some(mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) }),
  )]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, Some(options)).await?;
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

  let factor = ("password_1".to_owned(), mfkdf2::derive::factors::password("Tr0ubd4dour").await?);

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
    ("password_1".to_owned(), mfkdf2::derive::factors::password("wrong_password").await.unwrap());

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
      Some(mfkdf2::setup::factors::password::PasswordOptions {
        id: Some("password_1".to_string()),
      }),
    ),
    mfkdf2::setup::factors::password(
      "hunter2",
      Some(mfkdf2::setup::factors::password::PasswordOptions {
        id: Some("password_2".to_string()),
      }),
    ),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options { threshold: Some(1), ..Default::default() };
  let key = mfkdf2::setup::key(factors, Some(options)).await?;
  Ok(key)
}

#[tokio::test]
async fn test_key_setup_threshold() -> () { let key = mock_threshold_mfkdf2().await.unwrap(); }

#[tokio::test]
async fn test_key_derive_threshold() -> () {
  let key = mock_threshold_mfkdf2().await.unwrap();
  println!("Setup key: {}", key);

  let factor =
    ("password_1".to_owned(), mfkdf2::derive::factors::password("Tr0ubd4dour").await.unwrap());

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors).await.unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);

  let factor =
    ("password_2".to_owned(), mfkdf2::derive::factors::password("hunter2").await.unwrap());

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
      Some(mfkdf2::setup::factors::password::PasswordOptions {
        id: Some("password_1".to_string()),
      }),
    ),
    mfkdf2::setup::factors::question(
      "Paris",
      Some(mfkdf2::setup::factors::question::QuestionOptions {
        id:       Some("question_1".to_string()),
        question: "What is the capital of France?".to_string(),
      }),
    ),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key(factors, Some(options)).await?;
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
    ("password_1".to_owned(), mfkdf2::derive::factors::password("Tr0ubd4dour").await.unwrap());
  let factor_question = (
    "question_1".to_owned(),
    mfkdf2::derive::factors::question("Paris").unwrap()("value".into()).await.unwrap(),
  );

  let factors = HashMap::from([factor_password, factor_question]);

  let derived_key = mfkdf2::derive::key(key.policy.clone(), factors).await.unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);
}
