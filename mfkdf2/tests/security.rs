mod common;
use std::{
  collections::HashMap,
  time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose};
use mfkdf2::{
  constants::SECRET_SHARING_POLY,
  definitions::MFKDF2Options,
  derive,
  error::MFKDF2Error,
  otpauth::{HashAlgorithm, generate_otp_token},
  policy,
  policy::PolicySetupOptions,
  setup::{
    self,
    factors::{hotp::HOTPOptions, password::PasswordOptions, totp::TOTPOptions},
  },
};
use rand_chacha::rand_core::{RngCore, SeedableRng};

// Helper function to perform XOR operation on two byte arrays
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> { a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect() }

// Helper function to generate TOTP code from secret and current time
fn generate_totp_code(secret: &[u8], step: u64, hash: &HashAlgorithm, digits: u32) -> u32 {
  let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
  let counter = now / step;
  generate_otp_token(secret, counter, hash, digits)
}

#[test]
fn factor_fungibility_correct() -> Result<(), MFKDF2Error> {
  let setup = policy::setup(
    policy::and(
      setup::factors::password("password1", PasswordOptions { id: Some("password1".to_string()) })?,
      setup::factors::password("password2", PasswordOptions { id: Some("password2".to_string()) })?,
    )?,
    PolicySetupOptions::default(),
  )?;

  let derive = policy::derive(
    &setup.policy,
    &HashMap::from([
      ("password1".to_string(), derive::factors::password("password1")?),
      ("password2".to_string(), derive::factors::password("password2")?),
    ]),
    None,
  )?;

  assert_eq!(derive.key, setup.key);

  Ok(())
}

#[test]
fn factor_fungibility_incorrect() {
  let setup = policy::setup(
    policy::and(
      setup::factors::password("password1", PasswordOptions { id: Some("password1".to_string()) })
        .unwrap(),
      setup::factors::password("password2", PasswordOptions { id: Some("password2".to_string()) })
        .unwrap(),
    )
    .unwrap(),
    PolicySetupOptions::default(),
  )
  .unwrap();

  let derive = policy::derive(
    &setup.policy,
    &HashMap::from([
      ("password1".to_string(), derive::factors::password("password2").unwrap()),
      ("password2".to_string(), derive::factors::password("password1").unwrap()),
    ]),
    Some(false),
  )
  .unwrap();

  assert_ne!(derive.key, setup.key);
}

#[test]
fn share_indistinguishability_share_size() -> Result<(), MFKDF2Error> {
  let mut rng = rand_chacha::ChaCha20Rng::from_seed([10u8; 32]);

  let mut secret = [0u8; 32];
  rng.fill_bytes(&mut secret);

  let sss = ssskit::SecretSharing::<SECRET_SHARING_POLY>(1);
  let shares1 = sss.dealer_rng(&secret, &mut rng).take(3).collect::<Vec<_>>();
  assert_eq!(shares1.len(), 3);
  for share in shares1.iter() {
    assert_eq!(share.y.len(), 32);
  }

  let combined1 = sss.recover([&Some(shares1[0].clone()), &None, &None]).unwrap();
  assert_eq!(combined1, secret);

  let combined2 = sss.recover([&None, &None, &Some(shares1[2].clone())]).unwrap();
  assert_eq!(combined2, secret);

  let sss = ssskit::SecretSharing::<SECRET_SHARING_POLY>(2);
  let shares2 = sss.dealer_rng(&secret, &mut rng).take(3).collect::<Vec<_>>();
  assert_eq!(shares2.len(), 3);
  for share in shares2.iter() {
    assert_eq!(share.y.len(), 32);
  }
  let combined3 =
    sss.recover([&Some(shares2[0].clone()), &Some(shares2[1].clone()), &None]).unwrap();
  assert_eq!(combined3, secret);
  let combined4 =
    sss.recover([&None, &Some(shares2[1].clone()), &Some(shares2[2].clone())]).unwrap();
  assert_eq!(combined4, secret);

  let sss = ssskit::SecretSharing::<SECRET_SHARING_POLY>(3);
  let shares3 = sss.dealer_rng(&secret, &mut rng).take(3).collect::<Vec<_>>();
  assert_eq!(shares3.len(), 3);
  for share in shares3.iter() {
    assert_eq!(share.y.len(), 32);
  }
  let combined5 = sss
    .recover([&Some(shares3[0].clone()), &Some(shares3[1].clone()), &Some(shares3[2].clone())])
    .unwrap();
  assert_eq!(combined5, secret);

  Ok(())
}

#[test]
fn share_encryption_correct() -> Result<(), MFKDF2Error> {
  // Setup with two password factors using direct key setup
  let setup = setup::key(
    &[
      setup::factors::password("password1", PasswordOptions { id: Some("password1".to_string()) })?,
      setup::factors::password("password2", PasswordOptions { id: Some("password2".to_string()) })?,
    ],
    MFKDF2Options::default(),
  )?;

  // Get the first factor's material and compute the share manually
  let materialp1 = derive::factors::password("password1")?;
  let padp1 = general_purpose::STANDARD.decode(&setup.policy.factors[0].pad)?;
  let salt_bytes = general_purpose::STANDARD.decode(&setup.policy.factors[0].salt)?;
  let stretchedp1 = crate::common::hkdf_sha256_with_info(&materialp1.data(), &salt_bytes, &[]);
  let sharep1 = xor(&padp1, &stretchedp1);

  // Derive the key normally
  let mut derive = policy::derive(
    &setup.policy.clone(),
    &HashMap::from([
      ("password1".to_string(), derive::factors::password("password1")?),
      ("password2".to_string(), derive::factors::password("password2")?),
    ]),
    None,
  )?;

  assert_eq!(derive.key, setup.key);

  // Recover factor with new password - remove old and add new
  derive.recover_factor(setup::factors::password("newPassword1", PasswordOptions {
    id: Some("password1".to_string()),
  })?)?;

  // Try to derive with old password - should fail
  let derive2f = policy::derive(
    &derive.policy,
    &HashMap::from([
      ("password1".to_string(), derive::factors::password("password1")?),
      ("password2".to_string(), derive::factors::password("password2")?),
    ]),
    Some(false),
  )?;
  assert_ne!(derive2f.key, setup.key);

  // Derive with new password - should succeed
  let mut derive2 = policy::derive(
    &derive.policy,
    &HashMap::from([
      ("password1".to_string(), derive::factors::password("newPassword1")?),
      ("password2".to_string(), derive::factors::password("password2")?),
    ]),
    None,
  )?;
  assert_eq!(derive2.key, setup.key);

  // Compute share for the new password
  let materialp3 = derive::factors::password("newPassword1")?;
  let padp3 = general_purpose::STANDARD.decode(&derive.policy.factors[0].pad)?;
  let salt_bytes3 = general_purpose::STANDARD.decode(&derive.policy.factors[0].salt)?;
  let stretchedp3 = crate::common::hkdf_sha256_with_info(&materialp3.data(), &salt_bytes3, &[]);
  let sharep3 = xor(&padp3, &stretchedp3);

  // Recover factor again with another new password
  derive2.recover_factor(setup::factors::password("newPassword2", PasswordOptions {
    id: Some("password1".to_string()),
  })?)?;

  // Derive with the second new password - should succeed
  let derive3 = policy::derive(
    &derive2.policy,
    &HashMap::from([
      ("password1".to_string(), derive::factors::password("newPassword2")?),
      ("password2".to_string(), derive::factors::password("password2")?),
    ]),
    None,
  )?;
  assert_eq!(derive3.key, setup.key);

  // The shares should be different
  assert_ne!(sharep1, sharep3);

  Ok(())
}

#[test]
fn factor_secret_encryption_hotp() -> Result<(), MFKDF2Error> {
  // Setup HOTP factor with specific secret
  let secret = b"abcdefghijklmnopqrst".to_vec();
  let setup = setup::key(
    &[setup::factors::hotp::hotp(HOTPOptions {
      secret: Some(secret.clone()),
      ..Default::default()
    })?],
    MFKDF2Options::default(),
  )?;

  // Get the pad from the first factor's params
  let params = &&setup.policy.factors[0].params;
  let pad_b64 = params["pad"].as_str().unwrap();
  let pad = general_purpose::STANDARD.decode(pad_b64)?;

  // XOR the pad with the original secret
  let recover = xor(&pad, &secret);
  let recover_hex = hex::encode(&recover);

  // Get the first part of the setup key
  let key_hex = hex::encode(&setup.key);
  let key_prefix = &key_hex[..recover_hex.len()];

  // The recovered value should not equal the key prefix
  assert_ne!(recover_hex, key_prefix);

  // Derive with the correct HOTP code
  let derive1 = policy::derive(
    &setup.policy,
    &HashMap::from([("hotp".to_string(), derive::factors::hotp(241063)?)]),
    None,
  )?;

  assert_eq!(derive1.key, setup.key);

  Ok(())
}

#[test]
fn factor_secret_encryption_totp() -> Result<(), MFKDF2Error> {
  // Setup TOTP factor with specific secret and time
  let secret = b"abcdefghijklmnopqrst".to_vec();
  let setup = setup::key(
    &[setup::factors::totp::totp(TOTPOptions {
      secret: Some(secret.clone()),
      time: Some(1),
      ..Default::default()
    })?],
    MFKDF2Options::default(),
  )?;

  // Get the pad from the first factor's params
  let params = &&setup.policy.factors[0].params;
  let pad_b64 = params["pad"].as_str().unwrap();
  let pad = general_purpose::STANDARD.decode(pad_b64)?;

  // XOR the pad with the original secret
  let recover = xor(&pad, &secret);
  let recover_hex = hex::encode(&recover);

  // Get the first part of the setup key
  let key_hex = hex::encode(&setup.key);
  let key_prefix = &key_hex[..recover_hex.len()];

  // The recovered value should not equal the key prefix
  assert_ne!(recover_hex, key_prefix);

  // Derive with the correct TOTP code
  let derive1 = policy::derive(
    &setup.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        953265,
        Some(derive::factors::totp::TOTPDeriveOptions { time: Some(1), oracle: None }),
      )?,
    )]),
    None,
  )?;

  assert_eq!(derive1.key, setup.key);

  Ok(())
}

#[test]
fn totp_dynamic_no_oracle() -> Result<(), MFKDF2Error> {
  // Setup TOTP factor with default options
  let setup =
    setup::key(&[setup::factors::totp::totp(TOTPOptions::default())?], MFKDF2Options::default())?;

  // Get the secret from the setup outputs
  let outputs = setup.outputs.get("totp").unwrap();
  let secret = outputs["secret"]
    .as_array()
    .unwrap()
    .iter()
    .map(|v| v.as_u64().unwrap() as u8)
    .collect::<Vec<u8>>();
  let step = outputs["period"].as_u64().unwrap();
  let algorithm_str = outputs["algorithm"].as_str().unwrap();
  let hash = match algorithm_str {
    "sha1" => HashAlgorithm::Sha1,
    "sha256" => HashAlgorithm::Sha256,
    "sha512" => HashAlgorithm::Sha512,
    _ => HashAlgorithm::Sha1,
  };
  let digits = outputs["digits"].as_u64().unwrap() as u32;

  // Derive multiple times with the same oracle
  let derive1 = policy::derive(
    &setup.policy.clone(),
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(generate_totp_code(&secret, step, &hash, digits), None)?,
    )]),
    None,
  )?;

  let derive2 = policy::derive(
    &derive1.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(generate_totp_code(&secret, step, &hash, digits), None)?,
    )]),
    None,
  )?;

  let derive3 = policy::derive(
    &derive2.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(generate_totp_code(&secret, step, &hash, digits), None)?,
    )]),
    None,
  )?;

  // All derivations should produce the same key
  assert_eq!(derive1.key, setup.key);
  assert_eq!(derive2.key, setup.key);
  assert_eq!(derive3.key, setup.key);

  Ok(())
}

#[test]
fn totp_dynamic_valid_fixed_oracle() {
  // Create oracle with fixed values for 87600 steps (30 seconds each)
  let mut oracle = HashMap::new();
  let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
  let mut rounded_time = now - (now % (30 * 1000)); // Round to nearest 30 seconds

  for _i in 0..87600 {
    oracle.insert(rounded_time, 123456); // Fixed oracle value
    rounded_time += 30 * 1000;
  }

  // Setup TOTP factor with oracle
  let setup = setup::key(
    &[setup::factors::totp::totp(TOTPOptions {
      oracle: Some(oracle.clone()),
      ..Default::default()
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  // Get the secret from the setup outputs
  let outputs = setup.outputs.get("totp").unwrap();
  let secret = outputs["secret"]
    .as_array()
    .unwrap()
    .iter()
    .map(|v| v.as_u64().unwrap() as u8)
    .collect::<Vec<u8>>();
  let step = outputs["period"].as_u64().unwrap();
  let algorithm_str = outputs["algorithm"].as_str().unwrap();
  let hash = match algorithm_str {
    "sha1" => HashAlgorithm::Sha1,
    "sha256" => HashAlgorithm::Sha256,
    "sha512" => HashAlgorithm::Sha512,
    _ => HashAlgorithm::Sha1,
  };
  let digits = outputs["digits"].as_u64().unwrap() as u32;

  let derive1 = policy::derive(
    &setup.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle.clone()),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    None,
  )
  .unwrap();

  let derive2 = policy::derive(
    &derive1.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle.clone()),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    None,
  )
  .unwrap();

  let derive3 = policy::derive(
    &derive2.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle.clone()),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    None,
  )
  .unwrap();

  assert_eq!(derive1.key, setup.key);
  assert_eq!(derive2.key, setup.key);
  assert_eq!(derive3.key, setup.key);
}

#[test]
fn totp_dynamic_invalid_fixed_oracle() {
  // Create oracle with fixed values for 87600 steps (30 seconds each)
  let mut oracle = HashMap::new();
  let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
  let mut rounded_time = now - (now % (30 * 1000)); // Round to nearest 30 seconds

  for _i in 0..87600 {
    oracle.insert(rounded_time, 123456); // Fixed oracle value
    rounded_time += 30 * 1000;
  }

  // Setup TOTP factor with oracle
  let setup = setup::key(
    &[setup::factors::totp::totp(TOTPOptions {
      oracle: Some(oracle.clone()),
      ..Default::default()
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  // Get the secret from the setup outputs
  let outputs = setup.outputs.get("totp").unwrap();
  let secret = outputs["secret"]
    .as_array()
    .unwrap()
    .iter()
    .map(|v| v.as_u64().unwrap() as u8)
    .collect::<Vec<u8>>();
  let step = outputs["period"].as_u64().unwrap();
  let algorithm_str = outputs["algorithm"].as_str().unwrap();
  let hash = match algorithm_str {
    "sha1" => HashAlgorithm::Sha1,
    "sha256" => HashAlgorithm::Sha256,
    "sha512" => HashAlgorithm::Sha512,
    _ => HashAlgorithm::Sha1,
  };
  let digits = outputs["digits"].as_u64().unwrap() as u32;

  // Create a different oracle with different values
  let mut oracle2 = HashMap::new();
  let mut rounded_time = now - (now % (30 * 1000)); // Round to nearest 30 seconds
  for _i in 0..87600 {
    oracle2.insert(rounded_time, 654321); // Different fixed oracle value
    rounded_time += 30 * 1000;
  }

  // Derive with the different oracle - this should produce different keys
  let derive1 = policy::derive(
    &setup.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle2.clone()),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  let derive2 = policy::derive(
    &derive1.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle2.clone()),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  let derive3 = policy::derive(
    &derive2.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle2),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  assert_ne!(derive1.key, setup.key);
  assert_ne!(derive2.key, setup.key);
  assert_ne!(derive3.key, setup.key);
}

#[test]
fn totp_dynamic_valid_dynamic_oracle() {
  // Create oracle with dynamic values for 87600 steps (30 seconds each)
  let mut oracle = HashMap::new();
  let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
  let mut rounded_time = now - (now % (30 * 1000)); // Round to nearest 30 seconds

  for i in 0..87600 {
    oracle.insert(rounded_time, 100000 + i as u32); // Unique code for each time
    rounded_time += 30 * 1000;
  }

  // Setup TOTP factor with oracle
  let setup = setup::key(
    &[setup::factors::totp::totp(TOTPOptions {
      oracle: Some(oracle.clone()),
      ..Default::default()
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  // Get the secret from the setup outputs
  let outputs = setup.outputs.get("totp").unwrap();
  let secret = outputs["secret"]
    .as_array()
    .unwrap()
    .iter()
    .map(|v| v.as_u64().unwrap() as u8)
    .collect::<Vec<u8>>();
  let step = outputs["period"].as_u64().unwrap();
  let algorithm_str = outputs["algorithm"].as_str().unwrap();
  let hash = match algorithm_str {
    "sha1" => HashAlgorithm::Sha1,
    "sha256" => HashAlgorithm::Sha256,
    "sha512" => HashAlgorithm::Sha512,
    _ => HashAlgorithm::Sha1,
  };
  let digits = outputs["digits"].as_u64().unwrap() as u32;

  // Derive multiple times with the same oracle (should succeed)
  let derive1 = policy::derive(
    &setup.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle.clone()),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  let derive2 = policy::derive(
    &derive1.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle.clone()),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  let derive3 = policy::derive(
    &derive2.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        generate_totp_code(&secret, step, &hash, digits),
        Some(derive::factors::totp::TOTPDeriveOptions {
          oracle: Some(oracle),
          ..Default::default()
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  // All derivations should produce the same key
  assert_eq!(derive1.key, setup.key);
  assert_eq!(derive2.key, setup.key);
  assert_eq!(derive3.key, setup.key);
}

#[test]
fn totp_dynamic_invalid_dynamic_oracle() {
  // Create oracle with dynamic values for 87600 steps (30 seconds each)
  let mut oracle = HashMap::new();
  let mut date = 1650430806597u64;
  date -= date % (30 * 1000); // round to the nearest 30 seconds

  for i in 0..87600 {
    oracle.insert(date, 100000 + i as u32); // unique code for each time
    date += 30 * 1000; // 30 seconds
  }

  // Create a different oracle with fixed values
  let mut oracle2 = HashMap::new();
  let mut date = 1650430806597u64;
  date -= date % (30 * 1000); // round to the nearest 30 seconds

  for _i in 0..87600 {
    oracle2.insert(date, 654321);
    date += 30 * 1000; // 30 seconds
  }

  // Setup TOTP factor with specific secret and time
  let setup = setup::key(
    &[setup::factors::totp::totp(TOTPOptions {
      secret: Some(b"abcdefghijklmnopqrst".to_vec()),
      time: Some(1650430806597),
      oracle: Some(oracle.clone()),
      ..Default::default()
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  // Derive with different oracle and different times/codes
  let derive1 = policy::derive(
    &setup.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        528258,
        Some(derive::factors::totp::TOTPDeriveOptions {
          time:   Some(1650430943604),
          oracle: Some(oracle2.clone()),
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  let derive2 = policy::derive(
    &derive1.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        99922,
        Some(derive::factors::totp::TOTPDeriveOptions {
          time:   Some(1650430991083),
          oracle: Some(oracle2.clone()),
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  let derive3 = policy::derive(
    &derive1.policy,
    &HashMap::from([(
      "totp".to_string(),
      derive::factors::totp(
        398884,
        Some(derive::factors::totp::TOTPDeriveOptions {
          time:   Some(1650431018392),
          oracle: Some(oracle2),
        }),
      )
      .unwrap(),
    )]),
    Some(false),
  )
  .unwrap();

  // All derivations should produce different keys due to oracle mismatch
  assert_ne!(derive1.key, setup.key);
  assert_ne!(derive2.key, setup.key);
  assert_ne!(derive3.key, setup.key);
}
