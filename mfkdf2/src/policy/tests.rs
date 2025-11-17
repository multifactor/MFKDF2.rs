use std::collections::HashMap;

use rstest::rstest;

use crate::{
  derive, otpauth,
  policy::{
    self, Policy,
    logic::{all, and, any, at_least, or},
    setup::PolicySetupOptions,
  },
  setup::factors,
};

// Helper to create a factor by name and id for policy tests
fn create_policy_factor(name: &str, id: &str) -> crate::definitions::MFKDF2Factor {
  match name {
    "password" =>
      factors::password("password", factors::password::PasswordOptions { id: Some(id.to_string()) })
        .unwrap(),
    "hotp" => factors::hotp(factors::hotp::HOTPOptions {
      id:     Some("hotp".to_string()),
      secret: Some(vec![0u8; 20]),
      digits: 6,
      hash:   otpauth::HashAlgorithm::Sha256,
      issuer: "MFKDF".to_string(),
      label:  "test".to_string(),
    })
    .unwrap(),
    "totp" => factors::totp(factors::totp::TOTPOptions {
      id: Some(id.to_string()),
      secret: Some(vec![0u8; 20]),
      ..Default::default()
    })
    .unwrap(),
    "question" => factors::question("answer", factors::question::QuestionOptions {
      id:       Some(id.to_string()),
      question: Some("?".to_string()),
    })
    .unwrap(),
    _ => panic!("Unknown factor type: {}", name),
  }
}

// Helper to create a derive factor by name and id for policy tests
fn create_policy_derive_factor(
  name: &str,
  id: &str,
  policy: &crate::policy::Policy,
) -> (String, crate::definitions::MFKDF2Factor) {
  match name {
    "password" => (id.to_string(), derive::factors::password("password").unwrap()),
    "question" => (id.to_string(), derive::factors::question("answer").unwrap()),
    "hotp" => {
      let policy_ids: Vec<_> = policy.factors.iter().map(|f| f.id.as_str()).collect();
      println!("[DEBUG] Looking for id '{}' in policy ids: {:?}", id, policy_ids);
      let factor_policy = policy.factors.iter().find(|f| f.id == id).unwrap();
      let params = &factor_policy.params;
      let counter = params["counter"].as_u64().unwrap();
      let digits = params["digits"].as_u64().unwrap() as u8;
      let hash = serde_json::from_value(params["hash"].clone()).unwrap();
      let secret = vec![0u8; 20];
      let code = otpauth::generate_hotp_code(&secret, counter, &hash, digits);
      (id.to_string(), derive::factors::hotp(code).unwrap())
    },
    "totp" => {
      let policy_ids: Vec<_> = policy.factors.iter().map(|f| f.id.as_str()).collect();
      println!("[DEBUG] Looking for id '{}' in policy ids: {:?}", id, policy_ids);
      let factor_policy = policy.factors.iter().find(|f| f.id == id).unwrap();
      let params = &factor_policy.params;
      let time =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
      let step = params["step"].as_u64().unwrap();
      let hash = serde_json::from_value(params["hash"].clone()).unwrap();
      let digits = params["digits"].as_u64().unwrap() as u8;
      let counter = time as u64 / (step * 1000);
      let secret = vec![0u8; 20];
      let code = otpauth::generate_hotp_code(&secret, counter, &hash, digits);
      (id.to_string(), derive::factors::totp(code, None).unwrap())
    },
    _ => panic!("Unknown factor type: {}", name),
  }
}

#[rstest]
#[case(vec!["password", "hotp", "totp"], 2, vec![vec!["password", "hotp"], vec!["password",
"totp"]], 1)]
#[case(vec!["password", "hotp", "totp"], 3, vec![vec!["password", "hotp", "totp"]],
1)]
#[case(vec!["question", "password"], 2, vec![vec!["question", "password"]], 2)]
#[test]
fn policy_derivation_combinations(
  #[case] factor_names: Vec<&str>,
  #[case] threshold: usize,
  #[case] derive_combinations: Vec<Vec<&str>>,
  #[case] derivation_runs: u32,
) {
  // Assign unique ids for each factor for setup
  let factors: Vec<_> = factor_names.iter().map(|n| create_policy_factor(n, n)).collect();

  // Use at_least logic for threshold policies
  let policy_factor = at_least(threshold as u8, factors).unwrap();
  let setup = policy::setup::setup(policy_factor, PolicySetupOptions::default()).unwrap();

  let factors_policy: Policy =
    serde_json::from_value(setup.policy.factors[0].params.clone()).unwrap();

  for combo in derive_combinations {
    for _ in 0..derivation_runs {
      let derive_factors: HashMap<_, _> =
        combo.iter().map(|name| create_policy_derive_factor(name, name, &factors_policy)).collect();

      let derived = policy::derive::derive(setup.policy.clone(), derive_factors, None).unwrap();
      assert_eq!(derived.key, setup.key, "Failed for combination: {:?}", combo);
    }
  }
}

// Helper function to reduce boilerplate
fn create_policy_basic_1() -> policy::Policy {
  let p1 = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let q1 = factors::question("question", factors::question::QuestionOptions {
    id:       Some("id2".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();
  let h1 =
    factors::hotp(factors::hotp::HOTPOptions { id: Some("id3".to_string()), ..Default::default() })
      .unwrap();
  let t1 =
    factors::totp(factors::totp::TOTPOptions { id: Some("id4".to_string()), ..Default::default() })
      .unwrap();

  let or1 = or(p1, q1).unwrap();
  let or2 = or(h1, t1).unwrap();
  let policy_factor = and(or1, or2).unwrap();

  policy::setup::setup(policy_factor, PolicySetupOptions::default()).unwrap().policy
}

#[test]
fn validate_valid() {
  let policy = create_policy_basic_1();
  assert!(policy.validate());
}

#[test]
#[should_panic(expected = "DuplicateFactorId")]
fn validate_invalid() {
  let p1 = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let q1 = factors::question("question", factors::question::QuestionOptions {
    id:       Some("id2".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();
  let h1 = factors::hotp(factors::hotp::HOTPOptions {
    id: Some("id1".to_string()), // Duplicate ID
    ..Default::default()
  })
  .unwrap();
  let t1 = factors::totp(factors::totp::TOTPOptions {
    id: Some("id2".to_string()), // Duplicate ID
    ..Default::default()
  })
  .unwrap();

  let or1 = or(p1, q1).unwrap();
  let or2 = or(h1, t1).unwrap();
  let policy_factor = and(or1, or2).unwrap();

  policy::setup::setup(policy_factor, PolicySetupOptions::default()).unwrap();
}

#[test]
fn evaluate_basic_1() {
  let policy = create_policy_basic_1();

  assert!(!policy::evaluate::evaluate(&policy, vec!["id1".to_string(), "id2".to_string()]));
  assert!(!policy::evaluate::evaluate(&policy, vec!["id3".to_string(), "id4".to_string()]));
  assert!(policy::evaluate::evaluate(&policy, vec!["id1".to_string(), "id4".to_string()]));
  assert!(policy::evaluate::evaluate(&policy, vec!["id2".to_string(), "id3".to_string()]));
}

fn create_policy_basic_2() -> policy::Policy {
  let p1 = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let q1 = factors::question("question", factors::question::QuestionOptions {
    id:       Some("id2".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();
  let h1 =
    factors::hotp(factors::hotp::HOTPOptions { id: Some("id3".to_string()), ..Default::default() })
      .unwrap();
  let t1 =
    factors::totp(factors::totp::TOTPOptions { id: Some("id4".to_string()), ..Default::default() })
      .unwrap();

  let and1 = and(p1, q1).unwrap();
  let and2 = and(h1, t1).unwrap();
  let policy_factor = or(and1, and2).unwrap();

  policy::setup::setup(policy_factor, PolicySetupOptions::default()).unwrap().policy
}

#[test]
fn evaluate_basic_2() {
  let policy = create_policy_basic_2();

  assert!(policy::evaluate::evaluate(&policy, vec!["id1".to_string(), "id2".to_string()]));
  assert!(policy::evaluate::evaluate(&policy, vec!["id3".to_string(), "id4".to_string()]));
  assert!(!policy::evaluate::evaluate(&policy, vec!["id1".to_string(), "id4".to_string()]));
  assert!(!policy::evaluate::evaluate(&policy, vec!["id2".to_string(), "id3".to_string()]));
}

#[test]
fn derive_all() {
  let setup = policy::setup::setup(
    all(vec![
      factors::password("password1", factors::password::PasswordOptions {
        id: Some("id1".to_string()),
      })
      .unwrap(),
      factors::password("password2", factors::password::PasswordOptions {
        id: Some("id2".to_string()),
      })
      .unwrap(),
      factors::question("question", factors::question::QuestionOptions {
        id:       Some("id3".to_string()),
        question: Some("?".to_string()),
      })
      .unwrap(),
    ])
    .unwrap(),
    PolicySetupOptions::default(),
  )
  .unwrap();

  let derived = policy::derive::derive(
    setup.policy,
    HashMap::from([
      ("id1".to_string(), derive::factors::password("password1").unwrap()),
      ("id2".to_string(), derive::factors::password("password2").unwrap()),
      ("id3".to_string(), derive::factors::question("question").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derived.key, setup.key);
}

#[test]
fn derive_any() {
  let setup = policy::setup::setup(
    any(vec![
      factors::password("password1", factors::password::PasswordOptions {
        id: Some("id1".to_string()),
      })
      .unwrap(),
      factors::password("password2", factors::password::PasswordOptions {
        id: Some("id2".to_string()),
      })
      .unwrap(),
      factors::question("question", factors::question::QuestionOptions {
        id:       Some("id3".to_string()),
        question: Some("?".to_string()),
      })
      .unwrap(),
    ])
    .unwrap(),
    PolicySetupOptions::default(),
  )
  .unwrap();

  let derived = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([("id1".to_string(), derive::factors::password("password1").unwrap())]),
    None,
  )
  .unwrap();
  assert_eq!(derived.key, setup.key);
}

#[test]
fn derive_at_least() {
  let setup = policy::setup::setup(
    at_least(2, vec![
      factors::password("password", factors::password::PasswordOptions {
        id: Some("id1".to_string()),
      })
      .unwrap(),
      factors::question("question", factors::question::QuestionOptions {
        id:       Some("id2".to_string()),
        question: Some("?".to_string()),
      })
      .unwrap(),
      factors::hotp(factors::hotp::HOTPOptions {
        id: Some("id3".to_string()),
        ..Default::default()
      })
      .unwrap(),
    ])
    .unwrap(),
    PolicySetupOptions::default(),
  )
  .unwrap();

  let derived = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([
      ("id1".to_string(), derive::factors::password("password").unwrap()),
      ("id2".to_string(), derive::factors::question("question").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derived.key, setup.key);
}

#[test]
fn derive_basic_1() {
  let p1 = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let q1 = factors::question("question", factors::question::QuestionOptions {
    id:       Some("id2".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();
  let p3 = factors::password("password3", factors::password::PasswordOptions {
    id: Some("id3".to_string()),
  })
  .unwrap();
  let p4 = factors::password("password4", factors::password::PasswordOptions {
    id: Some("id4".to_string()),
  })
  .unwrap();

  let or1 = or(p1, q1).unwrap();
  let or2 = or(p3, p4).unwrap();
  let policy_factor = and(or1, or2).unwrap();

  let setup = policy::setup::setup(policy_factor, PolicySetupOptions::default()).unwrap();

  let derive1 = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([
      ("id1".to_string(), derive::factors::password("password").unwrap()),
      ("id3".to_string(), derive::factors::password("password3").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derive1.key, setup.key);

  let derive2 = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([
      ("id1".to_string(), derive::factors::password("password").unwrap()),
      ("id4".to_string(), derive::factors::password("password4").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derive2.key, setup.key);

  let derive3 = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([
      ("id2".to_string(), derive::factors::question("question").unwrap()),
      ("id3".to_string(), derive::factors::password("password3").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derive3.key, setup.key);

  let derive4 = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([
      ("id2".to_string(), derive::factors::question("question").unwrap()),
      ("id4".to_string(), derive::factors::password("password4").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derive4.key, setup.key);
}

#[test]
fn derive_basic_2() {
  let p1 = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let q1 = factors::question("question", factors::question::QuestionOptions {
    id:       Some("id2".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();
  let p3 = factors::password("password3", factors::password::PasswordOptions {
    id: Some("id3".to_string()),
  })
  .unwrap();
  let p4 = factors::password("password4", factors::password::PasswordOptions {
    id: Some("id4".to_string()),
  })
  .unwrap();

  let and1 = and(p1, q1).unwrap();
  let and2 = and(p3, p4).unwrap();
  let policy_factor = or(and1, and2).unwrap();

  let setup = policy::setup::setup(policy_factor, PolicySetupOptions::default()).unwrap();

  let derive1 = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([
      ("id1".to_string(), derive::factors::password("password").unwrap()),
      ("id2".to_string(), derive::factors::question("question").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derive1.key, setup.key);

  let derive2 = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([
      ("id3".to_string(), derive::factors::password("password3").unwrap()),
      ("id4".to_string(), derive::factors::password("password4").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derive2.key, setup.key);
}

#[test]
fn derive_deep() {
  let p1 = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let q2 = factors::question("question2", factors::question::QuestionOptions {
    id:       Some("id2".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();
  let q3 = factors::question("question3", factors::question::QuestionOptions {
    id:       Some("id3".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();
  let p4 = factors::password("password4", factors::password::PasswordOptions {
    id: Some("id4".to_string()),
  })
  .unwrap();
  let p5 = factors::password("password5", factors::password::PasswordOptions {
    id: Some("id5".to_string()),
  })
  .unwrap();
  let p6 = factors::password("password6", factors::password::PasswordOptions {
    id: Some("id6".to_string()),
  })
  .unwrap();

  let or1 = or(q2, q3).unwrap();
  let or2 = or(p5, p6).unwrap();
  let and1 = and(p4, or2).unwrap();
  let and2 = and(or1, and1).unwrap();
  let policy_factor = and(p1, and2).unwrap();

  let setup = policy::setup::setup(policy_factor, PolicySetupOptions::default()).unwrap();

  let derive = policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([
      ("id1".to_string(), derive::factors::password("password").unwrap()),
      ("id2".to_string(), derive::factors::question("question2").unwrap()),
      ("id4".to_string(), derive::factors::password("password4").unwrap()),
      ("id6".to_string(), derive::factors::password("password6").unwrap()),
    ]),
    None,
  )
  .unwrap();
  assert_eq!(derive.key, setup.key);
}

#[test]
#[should_panic(expected = "DuplicateFactorId")]
fn errors_invalid_policy() {
  let p1 = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let p1_dup = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let q2 = factors::question("question2", factors::question::QuestionOptions {
    id:       Some("id2".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();

  let or1 = or(p1_dup, q2).unwrap();
  let and1 = and(p1, or1).unwrap();

  // This setup should fail because `derive` calls `policy.validate()`
  let setup = policy::setup::setup(and1, PolicySetupOptions::default()).unwrap();

  policy::derive::derive(setup.policy.clone(), HashMap::new(), None).unwrap();
}

#[test]
#[should_panic(expected = "InvalidThreshold")]
fn errors_invalid_factors() {
  let p1 = factors::password("password", factors::password::PasswordOptions {
    id: Some("id1".to_string()),
  })
  .unwrap();
  let q2 = factors::question("question2", factors::question::QuestionOptions {
    id:       Some("id2".to_string()),
    question: Some("?".to_string()),
  })
  .unwrap();
  let policy_factor = and(p1, q2).unwrap();
  let setup = policy::setup::setup(policy_factor, PolicySetupOptions::default()).unwrap();

  // Not enough factors to satisfy the policy
  policy::derive::derive(
    setup.policy.clone(),
    HashMap::from([("id1".to_string(), derive::factors::password("password").unwrap())]),
    None,
  )
  .unwrap();
}
