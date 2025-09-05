use std::collections::HashMap;

async fn setup_stack() -> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let stacked_factors = vec![
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

  let key = mfkdf2::setup::key(
    vec![
      mfkdf2::setup::factors::stack(stacked_factors, mfkdf2::setup::key::MFKDF2Options::default())
        .await?,
      mfkdf2::setup::factors::password(
        "password_3",
        mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_3".to_string()) },
      )?,
    ],
    mfkdf2::setup::key::MFKDF2Options { id: None, threshold: Some(1), salt: None },
  )
  .await?;
  Ok(key)
}

#[tokio::test]
async fn test_stack() {
  let key = setup_stack().await.unwrap();
  println!("Setup key: {}", key);
}

#[tokio::test]
async fn test_stack_derive() {
  let key = setup_stack().await.unwrap();
  println!("Setup key: {}", key);

  let derived_key = mfkdf2::derive::key(
    key.policy.clone(),
    HashMap::from([(
      "stack".to_string(),
      mfkdf2::derive::factors::stack(HashMap::from([
        ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap()),
        ("password_2".to_string(), mfkdf2::derive::factors::password("hunter2").unwrap()),
      ]))
      .unwrap(),
    )]),
  )
  .await
  .unwrap();
  println!("Derived key: {}", derived_key);

  assert_eq!(derived_key.key, key.key);

  let derived_key = mfkdf2::derive::key(
    key.policy,
    HashMap::from([(
      "password3".to_string(),
      mfkdf2::derive::factors::password("password3").unwrap(),
    )]),
  )
  .await
  .unwrap();
  println!("Derived key: {}", derived_key);
  assert_eq!(derived_key.key, key.key);
}

#[tokio::test]
#[should_panic]
async fn test_stack_derive_fail() {
  let key = setup_stack().await.unwrap();
  println!("Setup key: {}", key);

  let derived_key = mfkdf2::derive::key(
    key.policy,
    HashMap::from([(
      "password_3".to_string(),
      mfkdf2::derive::factors::password("wrong_password").unwrap(),
    )]),
  )
  .await
  .unwrap();
  println!("Derived key: {}", derived_key);
  assert_eq!(derived_key.key, key.key);
}

#[tokio::test]
#[should_panic]
async fn test_stack_derive_fail_second() {
  let key = setup_stack().await.unwrap();
  println!("Setup key: {}", key);

  let derived_key = mfkdf2::derive::key(
    key.policy.clone(),
    HashMap::from([(
      "stack".to_string(),
      mfkdf2::derive::factors::stack(HashMap::from([(
        "password_1".to_string(),
        mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap(),
      )]))
      .unwrap(),
    )]),
  )
  .await
  .unwrap();
  println!("Derived key: {}", derived_key);
  assert_eq!(derived_key.key, key.key);
}
