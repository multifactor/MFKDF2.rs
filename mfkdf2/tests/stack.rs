use std::collections::HashMap;

use hmac::{Hmac, Mac};
use mfkdf2::{policy::Policy, setup::factors::hmacsha1::HmacSha1Response};
use sha1::Sha1;

const HMACSHA1_SECRET: [u8; 20] = [
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14,
];

fn mock_setup_stack() -> Result<mfkdf2::definitions::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let stacked_factors = vec![
    mfkdf2::setup::factors::password(
      "Tr0ubd4dour",
      mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) },
    ),
    mfkdf2::setup::factors::question::question(
      "my secret answer",
      mfkdf2::setup::factors::question::QuestionOptions {
        id:       Some("question_1".to_string()),
        question: Some("What is my secret?".to_string()),
      },
    ),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let stacked_factors_2 = vec![
    mfkdf2::setup::factors::uuid::uuid(mfkdf2::setup::factors::uuid::UUIDOptions {
      id:   Some("uuid_1".to_string()),
      uuid: Some(uuid::Uuid::parse_str("f9bf78b9-54e7-4696-97dc-5e750de4c592").unwrap()),
    }),
    mfkdf2::setup::factors::hmacsha1(mfkdf2::setup::factors::hmacsha1::HmacSha1Options {
      id:     Some("hmacsha1_1".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    }),
  ]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let key = mfkdf2::setup::key(
    &[
      mfkdf2::setup::factors::stack(
        stacked_factors,
        mfkdf2::setup::factors::stack::StackOptions {
          id: Some("stack_1".to_string()),
          ..Default::default()
        },
      )?,
      mfkdf2::setup::factors::stack(
        stacked_factors_2,
        mfkdf2::setup::factors::stack::StackOptions {
          id: Some("stack_2".to_string()),
          ..Default::default()
        },
      )?,
      mfkdf2::setup::factors::password(
        "my-secure-password",
        mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_3".to_string()) },
      )?,
    ],
    mfkdf2::setup::key::MFKDF2Options { threshold: Some(1), ..Default::default() },
  )?;
  Ok(key)
}

#[test]
fn stack_derive() {
  let key = mock_setup_stack().unwrap();

  let derived_key = mfkdf2::derive::key(
    &key.policy,
    HashMap::from([(
      "stack_1".to_string(),
      mfkdf2::derive::factors::stack(HashMap::from([
        ("password_1".to_string(), mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap()),
        ("question_1".to_string(), mfkdf2::derive::factors::question("my secret answer").unwrap()),
      ]))
      .unwrap(),
    )]),
    true,
    false,
  )
  .unwrap();
  assert_eq!(derived_key.key, key.key);

  let derived_key = mfkdf2::derive::key(
    &key.policy,
    HashMap::from([(
      "password_3".to_string(),
      mfkdf2::derive::factors::password("my-secure-password").unwrap(),
    )]),
    false,
    false,
  )
  .unwrap();
  assert_eq!(derived_key.key, key.key);

  let stack_factor_policy = serde_json::from_value::<Policy>(
    derived_key.policy.factors.iter().find(|f| f.id == "stack_2").unwrap().params.clone(),
  )
  .unwrap();
  let factor_policy = stack_factor_policy.factors.iter().find(|f| f.id == "hmacsha1_1").unwrap();
  let params = &factor_policy.params;
  let challenge = hex::decode(params["challenge"].as_str().unwrap()).unwrap();
  let response: [u8; 20] = <Hmac<Sha1> as Mac>::new_from_slice(&HMACSHA1_SECRET)
    .unwrap()
    .chain_update(challenge)
    .finalize()
    .into_bytes()
    .into();
  let derived_key = mfkdf2::derive::key(
    &derived_key.policy,
    HashMap::from([(
      "stack_2".to_string(),
      mfkdf2::derive::factors::stack(HashMap::from([
        (
          "uuid_1".to_string(),
          mfkdf2::derive::factors::uuid(
            uuid::Uuid::parse_str("f9bf78b9-54e7-4696-97dc-5e750de4c592").unwrap(),
          )
          .unwrap(),
        ),
        (
          "hmacsha1_1".to_string(),
          mfkdf2::derive::factors::hmacsha1(HmacSha1Response::from(response)).unwrap(),
        ),
      ]))
      .unwrap(),
    )]),
    false,
    false,
  )
  .unwrap();
  assert_eq!(derived_key.key, key.key);
}

#[test]
#[should_panic]
fn stack_derive_fail() {
  let key = mock_setup_stack().unwrap();

  let derived_key = mfkdf2::derive::key(
    &key.policy,
    HashMap::from([(
      "password_3".to_string(),
      mfkdf2::derive::factors::password("wrong_password").unwrap(),
    )]),
    false,
    false,
  )
  .unwrap();
  assert_eq!(derived_key.key, key.key);
}

#[test]
#[should_panic]
fn stack_derive_fail_second() {
  let key = mock_setup_stack().unwrap();

  let derived_key = mfkdf2::derive::key(
    &key.policy,
    HashMap::from([(
      "stack".to_string(),
      mfkdf2::derive::factors::stack(HashMap::from([(
        "password_1".to_string(),
        mfkdf2::derive::factors::password("Tr0ubd4dour").unwrap(),
      )]))
      .unwrap(),
    )]),
    false,
    false,
  )
  .unwrap();
  assert_eq!(derived_key.key, key.key);
}

#[test]
fn stack_policy_json_schema_compliance() {
  let key = mock_setup_stack().unwrap();

  // Serialize the policy to JSON
  let policy_json = serde_json::to_string_pretty(&key.policy).unwrap();

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
}
