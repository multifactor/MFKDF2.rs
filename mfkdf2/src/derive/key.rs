use std::collections::HashMap;

use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose};
use sharks::{Share, Sharks};

use crate::{
  crypto::{decrypt, hkdf_sha256_with_info, hmacsha256},
  definitions::mfkdf_derived_key::MFKDF2DerivedKey,
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  policy::Policy,
  setup::{factors::MFKDF2Factor, key::MFKDF2Entropy},
};

pub fn key(
  policy: Policy,
  factors: HashMap<String, MFKDF2Factor>,
  verify: bool,
  stack: bool,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  let mut shares_bytes = Vec::new();
  let mut outputs = HashMap::new();
  let mut factors = factors.clone(); // TODO (@lonerapier): fix this
  let mut new_policy = policy.clone();

  for factor in new_policy.factors.iter_mut() {
    let material = match factors.get_mut(factor.id.as_str()) {
      Some(material) => material,
      None => {
        shares_bytes.push(None);
        continue;
      },
    };

    if material.kind() == "persisted" {
      shares_bytes.push(Some(material.data()));
    } else {
      material.factor_type.include_params(serde_json::from_str(&factor.params).unwrap())?;

      // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
      let salt_bytes = general_purpose::STANDARD.decode(&factor.salt)?;

      let stretched = hkdf_sha256_with_info(
        &material.data(),
        &salt_bytes,
        format!("mfkdf2:factor:pad:{}", factor.id).as_bytes(),
      );

      // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
      let pad = general_purpose::STANDARD.decode(&factor.pad)?;
      // TODO (@lonerapier): unpadding of bytes is needed
      let plaintext = decrypt(pad, &stretched);

      if let Some(ref factor_hint) = factor.hint {
        let buffer = hkdf_sha256_with_info(
          &stretched,
          &material.salt,
          format!("mfkdf2:factor:hint:{}", factor.id).as_bytes(),
        );

        let binary_string: String =
          buffer.iter().map(|byte| format!("{:08b}", byte)).collect::<Vec<_>>().join("");

        // Take the last `hint_len` characters
        let hint = binary_string
          .chars()
          .rev()
          .take(factor_hint.len())
          .collect::<Vec<_>>()
          .into_iter()
          .rev()
          .collect::<String>();

        if hint != *factor_hint {
          return Err(MFKDF2Error::HintMismatch(factor.id.clone()));
        }
      }

      // TODO (autoparallel): It would be preferred to know the size of this array at compile
      // time.
      shares_bytes.push(Some(plaintext));
      outputs.insert(factor.id.clone(), material.factor_type.derive().output().to_string());
    }
  }

  // only first 33 bytes are needed from the share due to byte encoding (x=1 + y=32)
  // TODO (@lonerapier): remove stupid clones by fixing sharks fork
  let shares_vec: Vec<Option<Share>> = shares_bytes
    .iter()
    .map(|opt| {
      opt
        .clone()
        .map(|b| Share::try_from(&b[..1 + 32]).map_err(|_| MFKDF2Error::TryFromVecError))
        .transpose()
    })
    .collect::<Result<Vec<Option<Share>>, _>>()?;

  let sharks = Sharks(policy.threshold);
  let secret = sharks
    .recover(&shares_vec.clone().into_iter().flatten().collect::<Vec<Share>>())
    .map_err(|_| MFKDF2Error::ShareRecoveryError)?;
  let secret_arr: [u8; 32] = secret[..32].try_into().map_err(|_| MFKDF2Error::TryFromVecError)?;
  let salt_bytes = general_purpose::STANDARD.decode(&policy.salt)?;

  // Generate key
  let mut kek = [0u8; 32];
  if stack {
    // stack key
    kek =
      hkdf_sha256_with_info(&secret, &salt_bytes, format!("mfkdf2:stack:{}", policy.id).as_bytes());
  } else {
    // default key
    Argon2::new(
      argon2::Algorithm::Argon2id,
      Version::default(),
      Params::new(
        argon2::Params::DEFAULT_M_COST + policy.memory,
        argon2::Params::DEFAULT_T_COST + policy.time,
        1,
        Some(32),
      )?,
    )
    .hash_password_into(&secret_arr, &salt_bytes, &mut kek)?;
  }

  let policy_key_bytes = general_purpose::STANDARD.decode(policy.key.clone())?;
  let key = decrypt(policy_key_bytes, &kek);

  for factor in new_policy.factors.iter_mut() {
    let material = match factors.get(factor.id.as_str()).cloned() {
      Some(material) => material,
      None => continue,
    };

    let params_key = hkdf_sha256_with_info(
      &key,
      &general_purpose::STANDARD.decode(&factor.salt)?,
      format!("mfkdf2:factor:params:{}", factor.id).as_bytes(),
    );
    let params = material.factor_type.params(params_key.into());
    factor.params = serde_json::to_string(&params)?;
  }

  let integrity_key = hkdf_sha256_with_info(&key, &salt_bytes, "mfkdf2:integrity".as_bytes());
  if verify {
    let integrity_data = policy.extract();
    let hmac = hmacsha256(&integrity_key, &integrity_data);
    let hmac = general_purpose::STANDARD.encode(hmac);
    if policy.hmac != hmac {
      return Err(MFKDF2Error::PolicyIntegrityCheckFailed);
    }
  }
  if !policy.hmac.is_empty() {
    let integrity_data = new_policy.extract();
    let digest = hmacsha256(&integrity_key, &integrity_data);
    let hmac = general_purpose::STANDARD.encode(digest);
    new_policy.hmac = hmac;
  }

  let original_shares = sharks
    .recover_shares(
      shares_vec.iter().map(|s| s.as_ref()).collect::<Vec<Option<&Share>>>(),
      policy.factors.len(),
    )
    .map_err(|_| MFKDF2Error::ShareRecoveryError)?;

  Ok(MFKDF2DerivedKey {
    policy: new_policy,
    key: key.to_vec(),
    secret: secret_arr.to_vec(),
    shares: original_shares.into_iter().map(|s| Vec::from(&s)).collect(),
    outputs,
    entropy: MFKDF2Entropy { real: 0, theoretical: 0 },
  })
}

#[uniffi::export(default(verify = true, stack = false))]
pub async fn derive_key(
  policy: Policy,
  factors: HashMap<String, MFKDF2Factor>,
  verify: bool,
  stack: bool,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  key(policy, factors, verify, stack)
}

#[cfg(test)]
mod tests {
  use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
  };

  use serde_json::Value;

  use super::*;
  use crate::{
    derive::factors::{
      hmacsha1::hmacsha1 as derive_hmacsha1, hotp::hotp as derive_hotp, ooba::ooba as derive_ooba,
      password::password as derive_password, totp::totp as derive_totp,
    },
    setup::{
      self,
      factors::{
        FactorType,
        hmacsha1::{HmacSha1Options, hmacsha1 as setup_hmacsha1},
        hotp::{HOTPOptions, generate_hotp_code, hotp as setup_hotp},
        ooba::{OobaOptions, ooba as setup_ooba},
        password::{PasswordOptions, password as setup_password},
        totp::{TOTPOptions, totp as setup_totp},
      },
      key::MFKDF2Options,
    },
  };

  const TEST_JWK: &str = r#"{
    "key_ops": ["encrypt", "decrypt"],
    "ext": true,
    "alg": "RSA-OAEP-256",
    "kty": "RSA",
    "n": "1jR1L4H7Wov2W3XWlw1OII-fh_YuzfbZgpMCeSIPUd5oPvyvRf8nshkclQ9EQy6QlCZPX0HzCqkGokppxirKisyjfAlremiL8H60t2aapN_T3eClJ3KUxyEO1cejWoKejD86OtL_DWc04odInpcRmFgAF8mgjbEZRD0oSzaGlr70Ezi8p0yhpMTFM2Ltn0LG6SJ2_LGQwpEFNFf7790IoNpx8vKIZq0Ok1dGhC808f2t0ZhVFmxYnR-fp1jxd5B9nYDkjyJbWQK4vPlpAOgHw9v8G2Cg2X1TX2Ywr19tB249es2NlOYrFRQugzPyKfuVYxpFgoJfMuP83SPx-RvK6w",
    "e": "AQAB"
  }"#;

  fn generate_ooba_setup_factor(id: &str) -> MFKDF2Factor {
    let options = OobaOptions {
      id:     Some(id.to_string()),
      length: Some(8),
      key:    Some(TEST_JWK.to_string()),
      params: Some(r#"{"foo":"bar"}"#.to_string()),
    };

    setup_ooba(options).unwrap()
  }

  const HMACSHA1_SECRET: [u8; 20] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
  ];

  #[tokio::test]
  async fn key_derivation_round_trip_password_only() {
    // Setup phase
    let mut setup_factor = setup_password("password123", PasswordOptions::default()).unwrap();
    setup_factor.id = Some("pwd".to_string());
    let setup_factors = vec![setup_factor.clone()];
    let setup_derived_key =
      setup::key::key(setup_factors, setup::key::MFKDF2Options::default()).await.unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();
    let mut derive_factor = derive_password("password123").unwrap();
    derive_factor.id = Some("pwd".to_string());
    derive_factors_map.insert("pwd".to_string(), derive_factor);

    let derived_key =
      key(setup_derived_key.policy.clone(), derive_factors_map.clone(), false, false).unwrap();

    let derived_key2 = key(derived_key.policy, derive_factors_map, false, false).unwrap();

    // Assertions
    assert_eq!(derived_key.secret, setup_derived_key.secret);
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.key, derived_key2.key);
  }

  #[tokio::test]
  async fn key_derivation_round_trip_password_and_hmac() {
    // Setup phase
    let mut setup_password_factor =
      setup_password("password123", PasswordOptions::default()).unwrap();
    setup_password_factor.id = Some("pwd".to_string());

    let mut setup_hmac_factor = setup_hmacsha1(HmacSha1Options {
      id:     Some("hmac".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    })
    .unwrap();
    setup_hmac_factor.id = Some("hmac".to_string());

    let setup_factors = vec![setup_password_factor.clone(), setup_hmac_factor.clone()];
    let setup_derived_key =
      setup::key::key(setup_factors, setup::key::MFKDF2Options::default()).await.unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // Password factor
    let mut derive_password_factor = derive_password("password123").unwrap();
    derive_password_factor.id = Some("pwd".to_string());
    derive_factors_map.insert("pwd".to_string(), derive_password_factor);

    // Hmac factor
    let policy_hmac_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hmac").unwrap();
    let params: Value = serde_json::from_str(&policy_hmac_factor.params).unwrap();
    let challenge = hex::decode(params["challenge"].as_str().unwrap()).unwrap();

    let secret = if let FactorType::HmacSha1(h) = &setup_hmac_factor.factor_type {
      &h.padded_secret[..20]
    } else {
      panic!()
    };
    let response = crate::crypto::hmacsha1(secret, &challenge);
    let mut derive_hmac_factor = derive_hmacsha1(response.into()).unwrap();
    derive_hmac_factor.id = Some("hmac".to_string());
    derive_factors_map.insert("hmac".to_string(), derive_hmac_factor);

    let derived_key =
      key(setup_derived_key.policy.clone(), derive_factors_map, false, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.secret, setup_derived_key.secret);
  }

  #[tokio::test]
  async fn key_derivation_round_trip_hotp_totp_ooba() {
    // Setup phase
    let mut setup_hotp_factor = setup_hotp(HOTPOptions::default()).unwrap();
    setup_hotp_factor.id = Some("hotp".to_string());
    let hotp = match setup_hotp_factor.factor_type {
      FactorType::HOTP(ref h) => h,
      _ => panic!("Wrong factor type"),
    };

    let mut setup_totp_factor = setup_totp(TOTPOptions::default()).unwrap();
    setup_totp_factor.id = Some("totp".to_string());
    let totp = match setup_totp_factor.factor_type {
      FactorType::TOTP(ref t) => t,
      _ => panic!("Wrong factor type"),
    };

    let mut setup_ooba_factor = generate_ooba_setup_factor("ooba");
    setup_ooba_factor.id = Some("ooba".to_string());

    let setup_factors =
      vec![setup_hotp_factor.clone(), setup_totp_factor.clone(), setup_ooba_factor.clone()];
    let setup_derived_key =
      setup::key::key(setup_factors, setup::key::MFKDF2Options::default()).await.unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // HOTP factor
    let policy_hotp_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
    let hotp_params: Value = serde_json::from_str(&policy_hotp_factor.params).unwrap();
    let hotp_padded_secret = hotp.options.secret.as_ref().unwrap();
    let counter = hotp_params["counter"].as_u64().unwrap();
    let correct_code = generate_hotp_code(
      &hotp_padded_secret[..20],
      counter,
      &hotp.options.hash,
      hotp.options.digits,
    );
    let mut derive_hotp_factor = derive_hotp(correct_code as u32).unwrap();
    derive_hotp_factor.id = Some("hotp".to_string());
    derive_factors_map.insert("hotp".to_string(), derive_hotp_factor);

    // TOTP factor
    let totp_padded_secret = totp.options.secret.as_ref().unwrap();
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    let counter = time as u64 / (totp.options.step * 1000);
    let totp_code = generate_hotp_code(
      &totp_padded_secret[..20],
      counter,
      &totp.options.hash,
      totp.options.digits,
    );
    let mut derive_totp_factor = derive_totp(totp_code as u32, None).unwrap();
    derive_totp_factor.id = Some("totp".to_string());
    derive_factors_map.insert("totp".to_string(), derive_totp_factor);

    // OOBA factor
    let policy_ooba_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "ooba").unwrap();
    let ooba_params: Value = serde_json::from_str(&policy_ooba_factor.params).unwrap();
    let ooba_code = ooba_params["params"]["code"].as_str().unwrap();
    let mut derive_ooba_factor = derive_ooba(ooba_code.to_string()).unwrap();
    derive_ooba_factor.id = Some("ooba".to_string());
    derive_factors_map.insert("ooba".to_string(), derive_ooba_factor);

    let derived_key =
      key(setup_derived_key.policy.clone(), derive_factors_map, true, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.secret, setup_derived_key.secret);
  }

  #[tokio::test]
  async fn key_derivation_threshold_2_of_3() {
    // Setup phase
    let mut setup_password_factor =
      setup_password("password123", PasswordOptions::default()).unwrap();
    setup_password_factor.id = Some("pwd".to_string());

    let mut setup_hotp_factor = setup_hotp(HOTPOptions::default()).unwrap();
    setup_hotp_factor.id = Some("hotp".to_string());
    let hotp = match setup_hotp_factor.factor_type {
      FactorType::HOTP(ref h) => h,
      _ => panic!("Wrong factor type"),
    };

    let mut setup_totp_factor = setup_totp(TOTPOptions::default()).unwrap();
    setup_totp_factor.id = Some("totp".to_string());

    let setup_factors =
      vec![setup_password_factor.clone(), setup_hotp_factor.clone(), setup_totp_factor.clone()];
    let options = setup::key::MFKDF2Options { threshold: Some(2), ..Default::default() };
    let setup_derived_key = setup::key::key(setup_factors, options).await.unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // Password factor
    let mut derive_password_factor = derive_password("password123").unwrap();
    derive_password_factor.id = Some("pwd".to_string());
    derive_factors_map.insert("pwd".to_string(), derive_password_factor);

    // HOTP factor
    let policy_hotp_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
    let hotp_params: Value = serde_json::from_str(&policy_hotp_factor.params).unwrap();
    let hotp_padded_secret = hotp.options.secret.as_ref().unwrap();
    let counter = hotp_params["counter"].as_u64().unwrap();
    let correct_code = generate_hotp_code(
      &hotp_padded_secret[..20],
      counter,
      &hotp.options.hash,
      hotp.options.digits,
    );
    let mut derive_hotp_factor = derive_hotp(correct_code as u32).unwrap();
    derive_hotp_factor.id = Some("hotp".to_string());
    derive_factors_map.insert("hotp".to_string(), derive_hotp_factor);

    // We are only providing 2 out of 3 factors
    let derived_key =
      key(setup_derived_key.policy.clone(), derive_factors_map, false, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.secret, setup_derived_key.secret);
  }

  #[tokio::test]
  async fn key_derivation_threshold_3_of_5() {
    // Setup phase
    let mut setup_password_factor =
      setup_password("password123", PasswordOptions::default()).unwrap();
    setup_password_factor.id = Some("pwd".to_string());

    let mut setup_hmac_factor = setup_hmacsha1(HmacSha1Options {
      id:     Some("hmac".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    })
    .unwrap();
    setup_hmac_factor.id = Some("hmac".to_string());
    let hmac_setup = match &setup_hmac_factor.factor_type {
      FactorType::HmacSha1(h) => h,
      _ => panic!("Wrong factor type"),
    };

    let mut setup_hotp_factor = setup_hotp(HOTPOptions::default()).unwrap();
    setup_hotp_factor.id = Some("hotp".to_string());
    let hotp = match setup_hotp_factor.factor_type {
      FactorType::HOTP(ref h) => h,
      _ => panic!("Wrong factor type"),
    };

    let mut setup_totp_factor = setup_totp(TOTPOptions::default()).unwrap();
    setup_totp_factor.id = Some("totp".to_string());

    let mut setup_ooba_factor = generate_ooba_setup_factor("ooba");
    setup_ooba_factor.id = Some("ooba".to_string());

    let setup_factors = vec![
      setup_password_factor.clone(),
      setup_hmac_factor.clone(),
      setup_hotp_factor.clone(),
      setup_totp_factor.clone(),
      setup_ooba_factor.clone(),
    ];
    let options = setup::key::MFKDF2Options { threshold: Some(3), ..Default::default() };
    let setup_derived_key = setup::key::key(setup_factors, options).await.unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // Password factor
    let mut derive_password_factor = derive_password("password123").unwrap();
    derive_password_factor.id = Some("pwd".to_string());
    derive_factors_map.insert("pwd".to_string(), derive_password_factor);

    // Hmac factor
    let policy_hmac_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hmac").unwrap();
    let params: Value = serde_json::from_str(&policy_hmac_factor.params).unwrap();
    let challenge = hex::decode(params["challenge"].as_str().unwrap()).unwrap();
    let secret = &hmac_setup.padded_secret[..20];
    let response = crate::crypto::hmacsha1(secret, &challenge);
    let mut derive_hmac_factor = derive_hmacsha1(response.into()).unwrap();
    derive_hmac_factor.id = Some("hmac".to_string());
    derive_factors_map.insert("hmac".to_string(), derive_hmac_factor);

    // HOTP factor
    let policy_hotp_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
    let hotp_params: Value = serde_json::from_str(&policy_hotp_factor.params).unwrap();
    let hotp_padded_secret = hotp.options.secret.as_ref().unwrap();
    let counter = hotp_params["counter"].as_u64().unwrap();
    let correct_code = generate_hotp_code(
      &hotp_padded_secret[..20],
      counter,
      &hotp.options.hash,
      hotp.options.digits,
    );
    let mut derive_hotp_factor = derive_hotp(correct_code as u32).unwrap();
    derive_hotp_factor.id = Some("hotp".to_string());
    derive_factors_map.insert("hotp".to_string(), derive_hotp_factor);

    // We are only providing 3 out of 5 factors
    let derived_key =
      key(setup_derived_key.policy.clone(), derive_factors_map, false, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.secret, setup_derived_key.secret);
  }

  #[tokio::test]
  async fn key_derivation_shares() {
    // Setup phase
    let setup_factors = vec![
      setup_password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap(),
      setup_password("password456", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap(),
      setup_password("password789", PasswordOptions { id: Some("pwd3".to_string()) }).unwrap(),
    ];
    let setup_derived_key =
      setup::key::key(setup_factors, MFKDF2Options { threshold: Some(2), ..Default::default() })
        .await
        .unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // Password factor
    let mut derive_password_factor = derive_password("password123").unwrap();
    derive_password_factor.id = Some("pwd1".to_string());
    derive_factors_map.insert("pwd1".to_string(), derive_password_factor);

    // Password factor
    let mut derive_password_factor = derive_password("password456").unwrap();
    derive_password_factor.id = Some("pwd2".to_string());
    derive_factors_map.insert("pwd2".to_string(), derive_password_factor);

    let derived_key =
      key(setup_derived_key.policy.clone(), derive_factors_map, true, false).unwrap();

    // Assertions
    assert_eq!(derived_key.shares, setup_derived_key.shares);

    let mut derive_factors_map = HashMap::new();

    // Password factor
    let mut derive_password_factor = derive_password("password789").unwrap();
    derive_password_factor.id = Some("pwd3".to_string());
    derive_factors_map.insert("pwd3".to_string(), derive_password_factor);

    // Password factor
    let mut derive_password_factor = derive_password("password456").unwrap();
    derive_password_factor.id = Some("pwd2".to_string());
    derive_factors_map.insert("pwd2".to_string(), derive_password_factor);

    let derived_key =
      key(setup_derived_key.policy.clone(), derive_factors_map, true, false).unwrap();

    // Assertions
    assert_eq!(derived_key.shares, setup_derived_key.shares);
  }
}
