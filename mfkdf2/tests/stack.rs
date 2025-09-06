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
        "my-secure-password",
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
      "password_3".to_string(),
      mfkdf2::derive::factors::password("my-secure-password").unwrap(),
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

#[tokio::test]
async fn test_stack_policy_json_schema_compliance() {
  let key = setup_stack().await.unwrap();

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

  for factor in factors {
    assert!(factor.get("id").is_some(), "Factor missing id field");
    assert!(factor.get("type").is_some(), "Factor missing type field");
    assert!(factor.get("pad").is_some(), "Factor missing pad field");
    assert!(factor.get("salt").is_some(), "Factor missing salt field");
    assert!(factor.get("secret").is_some(), "Factor missing secret field");
    assert!(factor.get("params").is_some(), "Factor missing params field");
  }

  println!("✅ Policy JSON schema compliance test passed!");
}
