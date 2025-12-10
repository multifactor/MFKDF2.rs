//! The core MFKDF2 algorithm serves as a foundational primitive for deriving a high-entropy
//! master key from a multi-factor policy. Key Derive phase takes a derived policy state βᵢ and
//! factor witnesses Wᵢⱼ, and reconstructs the master secret M, along with the next state βᵢ₊₁.
use std::{collections::HashMap, fmt::Write};

use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose};
use ssskit::{SecretSharing, Share};

use crate::{
  constants::SECRET_SHARING_POLY,
  crypto::{decrypt, hkdf_sha256_with_info, hmacsha256},
  definitions::{MFKDF2DerivedKey, MFKDF2Entropy, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  policy::Policy,
};

/// Performs `KeyDerive` on an existing policy and a set of derive‑time factor witnesses
///
/// This function implements the derive phase described in [`crate::derive`], taking a policy state
/// βᵢ and factor witnesses Wᵢⱼ, reconstructing the master secret M, regenerating the key‑encryption
/// key (KEK), decrypting the current key Kᵢ, and producing a fresh [`MFKDF2DerivedKey`] with
/// updated factor parameters and integrity metadata
///
/// # Arguments
///
/// * `policy`: [`Policy`] βᵢ produced during `KeySetup` that encodes threshold, helper data, and
///   encrypted Shamir shares
/// * `factors`: Derived [`MFKDF2Factor`] witnesses Wᵢⱼ
/// * `verify`: Policy verification flag to check the stored policy HMAC against the derived key
///   material and returns an error when the integrity check fails
/// * `stack`: Enables stack‑based factor derivation
///
/// # Returns
///
/// On success, returns an [`MFKDF2DerivedKey`] representing Kᵢ₊₁ with:
///
/// * A possibly updated [`Policy`] reflecting refreshed factor parameters and integrity HMAC
/// * A 32‑byte key `K`
/// * Recovered `secret` and Shamir shares consistent with the provided witnesses
/// * Per‑factor outputs produced by the factor derive algorithms
///
/// # Examples
///
/// Password and HMAC‑SHA1 round‑trip where `derive` reconstructs the same key and secret as setup
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   setup::{
/// #     self,
/// #     factors::{
/// #       hmacsha1::{HmacSha1Options, hmacsha1 as setup_hmacsha1},
/// #       password::{PasswordOptions, password as setup_password},
/// #     },
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive::{
/// #     self,
/// #     factors::{
/// #       password as derive_password,
/// #       hmacsha1 as derive_hmacsha1,
/// #     },
/// #   },
/// # };
/// # use hmac::{Mac, Hmac};
/// # use sha1::Sha1;
/// # const HMACSHA1_SECRET: [u8; 20] = [0u8; 20];
/// let password_factor =
///   setup_password("password123", PasswordOptions { id: Some("pwd".to_string()) })?;
/// let hmac_factor = setup_hmacsha1(HmacSha1Options {
///   secret: Some(HMACSHA1_SECRET.to_vec()),
///   ..Default::default()
/// })?;
///
/// let setup_key = setup::key(&[password_factor, hmac_factor.clone()], MFKDF2Options::default())?;
///
/// // Build derive‑time password witness
/// let derive_pwd = derive_password("password123")?;
///
/// // Build derive‑time HMAC witness using the challenge from policy
/// let policy_hmac = setup_key.policy.factors.iter().find(|f| f.id == "hmacsha1").unwrap();
/// let challenge = match &policy_hmac.params {
///   mfkdf2::definitions::factor::FactorParams::HmacSha1(p) => hex::decode(&p.challenge).unwrap(),
///   _ => unreachable!(),
/// };
/// let secret = if let mfkdf2::definitions::FactorType::HmacSha1(h) = &hmac_factor.factor_type {
///   &h.padded_secret[..20]
/// } else {
///   unreachable!()
/// };
/// let response: [u8; 20] = <Hmac<Sha1> as Mac>::new_from_slice(&HMACSHA1_SECRET)
///   .unwrap()
///   .chain_update(challenge)
///   .finalize()
///   .into_bytes()
///   .into();
/// let derive_hmac = derive_hmacsha1(response)?;
///
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("pwd".to_string(), derive_pwd), ("hmacsha1".to_string(), derive_hmac)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// assert_eq!(derived_key.secret, setup_key.secret);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// Threshold derivation with password, HOTP, and TOTP where only a 2‑of‑3 subset is supplied
///
/// ```rust
/// # use std::collections::HashMap;
/// # use std::time::{SystemTime, UNIX_EPOCH};
/// # use mfkdf2::{
/// #   otpauth::generate_otp_token,
/// #   setup::{
/// #     self,
/// #     factors::{
/// #       hotp::{HOTPOptions, hotp as setup_hotp},
/// #       password::{PasswordOptions, password as setup_password},
/// #       totp::{TOTPOptions, totp as setup_totp},
/// #     },
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive::factors::{password as derive_password, hotp as derive_hotp},
/// #   derive,
/// # };
/// let setup_pwd = setup_password("password123", PasswordOptions::default())?;
/// let setup_hotp = setup_hotp(HOTPOptions::default())?;
/// let setup_totp = setup_totp(TOTPOptions::default())?;
///
/// let options = MFKDF2Options { threshold: Some(2), ..MFKDF2Options::default() };
/// let setup_key =
///   setup::key(&[setup_pwd.clone(), setup_hotp.clone(), setup_totp.clone()], options)?;
///
/// let mut factors = HashMap::new();
///
/// // Password witness
/// let derive_pwd = derive_password("password123")?;
/// factors.insert("password".to_string(), derive_pwd);
///
/// // HOTP witness
/// let policy_hotp = setup_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
/// let (counter, hash, digits) = match &policy_hotp.params {
///   mfkdf2::definitions::factor::FactorParams::HOTP(p) => (p.counter, &p.hash, p.digits),
///   _ => unreachable!(),
/// };
/// let hotp = match setup_hotp.factor_type {
///   mfkdf2::definitions::FactorType::HOTP(ref h) => h,
///   _ => unreachable!(),
/// };
/// let hotp_code = generate_otp_token(&hotp.config.secret[..20], counter, hash, digits);
/// let derive_hotp = derive_hotp(hotp_code as u32)?;
/// factors.insert("hotp".to_string(), derive_hotp);
///
/// // Only 2 of the 3 factors are supplied
/// let derived_key = derive::key(&setup_key.policy, factors, false, false)?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// assert_eq!(derived_key.secret, setup_key.secret);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// Persisted factor example where a single HOTP factor is persisted during setup and later used
/// directly as a witness during derive alongside a password factor
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   derive,
/// #   setup::{
/// #     self,
/// #     factors::{
/// #       hotp::HOTPOptions,
/// #       password::{PasswordOptions, password as setup_password},
/// #     },
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive::factors::{persisted as derive_persisted, password as derive_password},
/// # };
/// let setup_factors = &[
///   setup::factors::hotp::hotp(HOTPOptions::default())?,
///   setup_password("password", PasswordOptions::default())?,
/// ];
/// let setup_key = setup::key(setup_factors, MFKDF2Options::default())?;
///
/// let persisted = setup_key.persist_factor("hotp");
/// let derived = derive::key(
///   &setup_key.policy,
///   HashMap::from([
///     ("hotp".to_string(), derive_persisted(persisted)?),
///     ("password".to_string(), derive_password("password")?),
///   ]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived.key, setup_key.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// # Errors
///
/// The function returns invalid key when the provided witnesses do not reconstruct a consistent set
/// of Shamir shares, for example when an OTP factor is incorrect
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   setup::{
/// #     self,
/// #     factors::hotp::{HOTPOptions, hotp as setup_hotp},
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive::factors::hotp as derive_hotp,
/// #   derive,
/// # };
/// let setup_key = setup::key(&[setup_hotp(HOTPOptions::default())?], MFKDF2Options::default())?;
///
/// // Deliberately wrong HOTP code
/// let wrong_hotp = derive_hotp(123456)?;
///
/// let derive_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("hotp".to_string(), wrong_hotp)]),
///   false,
///   false,
/// )?;
///
/// assert_ne!(derive_key.key, setup_key.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// The function returns `Err(MFKDF2Error::PolicyIntegrityCheckFailed)` when `verify` is `true` and
/// the stored policy HMAC does not match the recomputed integrity digest, for example when the
/// policy has been tampered with between setup and derive
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   setup::{
/// #     self,
/// #     factors::password::{PasswordOptions, password as setup_password},
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive::factors::password as derive_password,
/// #   derive,
/// # };
/// let setup_key = setup::key(
///   &[setup_password("password123", PasswordOptions { id: Some("password".to_string()) })?],
///   MFKDF2Options::default(),
/// )?;
///
/// let mut corrupted_policy = setup_key.policy.clone();
/// corrupted_policy.hmac = "corrupted".to_string();
///
/// let derive_factor = derive_password("password123")?;
/// let result = derive::key(
///   &corrupted_policy,
///   HashMap::from([("password".to_string(), derive_factor)]),
///   true,
///   false,
/// );
///
/// assert!(matches!(result, Err(mfkdf2::error::MFKDF2Error::PolicyIntegrityCheckFailed)));
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn key(
  policy: &Policy,
  factors: HashMap<String, MFKDF2Factor>,
  verify: bool,
  stack: bool,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  if factors.len() > 255 {
    return Err(MFKDF2Error::TooManyFactors);
  }

  let mut shares_bytes = Vec::new();
  let mut outputs = HashMap::new();
  let mut factors = factors;
  let mut new_policy = policy.clone();

  for factor in &new_policy.factors {
    let Some(material) = factors.get_mut(factor.id.as_str()) else {
      shares_bytes.push(None);
      continue;
    };

    if material.kind() == "persisted" {
      shares_bytes.push(Some(material.data()));
    } else {
      material.factor_type.include_params(factor.params.clone())?;

      // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
      let salt_bytes = general_purpose::STANDARD.decode(&factor.salt)?;

      let stretched = hkdf_sha256_with_info(
        &material.data(),
        &salt_bytes,
        format!("mfkdf2:factor:pad:{}", factor.id).as_bytes(),
      );

      // TODO (autoparallel): This should probably be done with a `MaybeUninit` array.
      let pad = general_purpose::STANDARD.decode(&factor.pad)?;
      let plaintext = decrypt(pad, &stretched);

      // TODO (autoparallel): It would be preferred to know the size of this array at compile
      // time.
      shares_bytes.push(Some(plaintext));
      outputs.insert(factor.id.clone(), material.factor_type.derive().output());
    }
  }

  let shares_vec: Vec<Option<Share<SECRET_SHARING_POLY>>> = shares_bytes
    .into_iter()
    .map(|opt| {
      opt.map(|b| Share::try_from(b.as_slice()).map_err(|_| MFKDF2Error::TryFromVec)).transpose()
    })
    .collect::<Result<Vec<Option<Share<SECRET_SHARING_POLY>>>, _>>()?;

  let sss = SecretSharing(policy.threshold);
  let secret = sss.recover(&shares_vec).map_err(|_| MFKDF2Error::ShareRecovery)?;
  #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
  let mut secret_arr: [u8; 32] = secret[..32].try_into().map_err(|_| MFKDF2Error::TryFromVec)?;
  let salt_bytes = general_purpose::STANDARD.decode(&policy.salt)?;

  // Generate key
  let mut kek = [0u8; 32];
  if stack {
    // stack key
    kek = hkdf_sha256_with_info(
      &secret_arr,
      &salt_bytes,
      format!("mfkdf2:stack:{}", policy.id).as_bytes(),
    );
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

  // Create an internal key for deriving separate keys for parameters, secret, and integrity
  let policy_key_bytes = general_purpose::STANDARD.decode(policy.key.as_bytes())?;
  let internal_key = decrypt(policy_key_bytes, &kek);

  // Perform integrity check
  #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
  let mut integrity_key =
    hkdf_sha256_with_info(&internal_key, &salt_bytes, "mfkdf2:integrity".as_bytes());
  if verify {
    let integrity_data = policy.extract();
    let digest = hmacsha256(&integrity_key, &integrity_data);
    let hmac = general_purpose::STANDARD.encode(digest);
    if policy.hmac != hmac {
      return Err(MFKDF2Error::PolicyIntegrityCheckFailed);
    }
  }

  for factor in &mut new_policy.factors {
    let Some(material) = factors.get(factor.id.as_str()) else {
      continue;
    };

    // Perform hint verification after policy integrity check
    if let Some(ref factor_hint) = factor.hint {
      let salt = general_purpose::STANDARD.decode(&factor.salt)?;
      let stretched = hkdf_sha256_with_info(
        &material.data(),
        &salt,
        format!("mfkdf2:factor:pad:{}", factor.id).as_bytes(),
      );

      let buffer = hkdf_sha256_with_info(
        &stretched,
        &salt,
        format!("mfkdf2:factor:hint:{}", factor.id).as_bytes(),
      );

      let binary_string = buffer.iter().fold(String::new(), |mut acc, byte| {
        write!(&mut acc, "{byte:08b}").unwrap();
        acc
      });

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

    let params_key = hkdf_sha256_with_info(
      &internal_key,
      &general_purpose::STANDARD.decode(&factor.salt)?,
      format!("mfkdf2:factor:params:{}", factor.id).as_bytes(),
    );
    let params = material.factor_type.derive().params(params_key.into())?;
    factor.params = params;
  }

  // Update the policy HMAC
  if !policy.hmac.is_empty() {
    let integrity_data = new_policy.extract();
    let digest = hmacsha256(&integrity_key, &integrity_data);
    let hmac = general_purpose::STANDARD.encode(digest);
    new_policy.hmac = hmac;
  }

  let original_shares = sss
    .recover_shares(
      shares_vec.iter().map(|s| s.as_ref()).collect::<Vec<Option<&Share<SECRET_SHARING_POLY>>>>(),
      policy.factors.len(),
    )
    .map_err(|_| MFKDF2Error::ShareRecovery)?;

  // derive a dedicated final key to ensure domain separation between internal and external keys
  let final_key: [u8; 32] = if stack {
    internal_key.try_into().map_err(|_| MFKDF2Error::TryFromVec)?
  } else {
    hkdf_sha256_with_info(&internal_key, &salt_bytes, "mfkdf2:key:final".as_bytes())
  };

  let result = MFKDF2DerivedKey {
    policy: new_policy,
    key: final_key.into(),
    secret: secret_arr.into(),
    shares: original_shares.into_iter().map(|s| Vec::from(&s)).collect(),
    outputs,
    entropy: MFKDF2Entropy { real: 0.0, theoretical: 0 },
  };

  #[cfg(feature = "zeroize")]
  {
    use zeroize::Zeroize;
    secret_arr.zeroize();
    kek.zeroize();
    integrity_key.zeroize();
  }

  Ok(result)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export(default(verify = true, stack = false)))]
async fn derive_key(
  policy: &Policy,
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

  use jsonwebtoken::jwk::Jwk;
  use rand::{RngCore, rngs::OsRng};
  use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
  use serde_json::{Value, json};
  use sha2::Sha256;

  use super::*;
  use crate::{
    definitions::{FactorType, MFKDF2Options},
    derive::{
      self,
      factors::{
        hmacsha1 as derive_hmacsha1, hotp as derive_hotp, ooba as derive_ooba,
        passkey as derive_passkey, password as derive_password, persisted, totp as derive_totp,
      },
    },
    otpauth::generate_otp_token,
    setup::{
      self,
      factors::{
        hmacsha1::{HmacSha1Options, hmacsha1 as setup_hmacsha1},
        hotp::{HOTPOptions, hotp as setup_hotp},
        ooba::{OobaOptions, ooba as setup_ooba},
        passkey::{PasskeyOptions, passkey as setup_passkey},
        password::{PasswordOptions, password as setup_password},
        totp::{TOTPOptions, totp as setup_totp},
      },
    },
  };

  fn keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let bits = 2048;
    let private_key =
      RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
  }

  fn jwk(key: &RsaPublicKey) -> Jwk {
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
    let jwk = json!({
      "key_ops": ["encrypt", "decrypt"],
      "ext": true,
      "alg": "RSA-OAEP-256",
      "kty": "RSA",
      "n": n,
      "e": e
    });
    serde_json::from_value(jwk).unwrap()
  }

  fn generate_ooba_setup_factor(id: &str, key: &RsaPublicKey) -> MFKDF2Factor {
    let options = OobaOptions {
      id:     Some(id.to_string()),
      length: Some(8),
      key:    Some(jwk(key)),
      params: Some(json!({"foo":"bar"})),
    };

    setup_ooba(options).unwrap()
  }

  const HMACSHA1_SECRET: [u8; 20] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
  ];

  #[test]
  fn key_derivation_round_trip_password_only() {
    // Setup phase
    let setup_derived_key = setup::key(
      &[setup_password("password123", PasswordOptions { id: Some("pwd".to_string()) }).unwrap()],
      MFKDF2Options::default(),
    )
    .unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();
    let mut derive_factor = derive_password("password123").unwrap();
    derive_factor.id = Some("pwd".to_string());
    derive_factors_map.insert("pwd".to_string(), derive_factor);

    let derived_key =
      key(&setup_derived_key.policy, derive_factors_map.clone(), false, false).unwrap();

    let derived_key2 = key(&derived_key.policy, derive_factors_map, false, false).unwrap();

    // Assertions
    assert_eq!(derived_key.secret, setup_derived_key.secret);
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.key, derived_key2.key);
  }

  #[test]
  fn key_derivation_round_trip_password_and_hmac() {
    // Setup phase
    let setup_password_factor =
      setup_password("password123", PasswordOptions { id: Some("pwd".to_string()) }).unwrap();

    let setup_hmac_factor = setup_hmacsha1(HmacSha1Options {
      id:     Some("hmac".to_string()),
      secret: Some(HMACSHA1_SECRET.to_vec()),
    })
    .unwrap();

    let setup_derived_key =
      setup::key(&[setup_password_factor, setup_hmac_factor.clone()], MFKDF2Options::default())
        .unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // Password factor
    let mut derive_password_factor = derive_password("password123").unwrap();
    derive_password_factor.id = Some("pwd".to_string());
    derive_factors_map.insert("pwd".to_string(), derive_password_factor);

    // Hmac factor
    let policy_hmac_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hmac").unwrap();
    let params = &policy_hmac_factor.params;
    let challenge = match params {
      crate::definitions::factor::FactorParams::HmacSha1(p) => hex::decode(&p.challenge).unwrap(),
      _ => panic!("Expected HmacSha1 params"),
    };

    let secret = if let FactorType::HmacSha1(h) = &setup_hmac_factor.factor_type {
      &h.padded_secret[..20]
    } else {
      panic!()
    };
    let response = crate::crypto::hmacsha1(secret, &challenge);
    let mut derive_hmac_factor = derive_hmacsha1(response).unwrap();
    derive_hmac_factor.id = Some("hmac".to_string());
    derive_factors_map.insert("hmac".to_string(), derive_hmac_factor);

    let derived_key = key(&setup_derived_key.policy, derive_factors_map, false, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.secret, setup_derived_key.secret);
  }

  #[test]
  fn key_derivation_round_trip_hotp_totp_ooba() {
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

    let (private_key, public_key) = keypair();
    let mut setup_ooba_factor = generate_ooba_setup_factor("ooba", &public_key);
    setup_ooba_factor.id = Some("ooba".to_string());

    let setup_derived_key = setup::key(
      &[setup_hotp_factor.clone(), setup_totp_factor.clone(), setup_ooba_factor.clone()],
      MFKDF2Options::default(),
    )
    .unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // HOTP factor
    let policy_hotp_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
    let hotp_params = &policy_hotp_factor.params;
    let counter = match hotp_params {
      crate::definitions::factor::FactorParams::HOTP(p) => p.counter,
      _ => panic!("Expected HOTP params"),
    };
    let correct_code =
      generate_otp_token(&hotp.config.secret[..20], counter, &hotp.config.hash, hotp.config.digits);
    let mut derive_hotp_factor = derive_hotp(correct_code as u32).unwrap();
    derive_hotp_factor.id = Some("hotp".to_string());
    derive_factors_map.insert("hotp".to_string(), derive_hotp_factor);

    // TOTP factor
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    let counter = time as u64 / (totp.config.step as u64 * 1000);
    let totp_code =
      generate_otp_token(&totp.config.secret[..20], counter, &totp.config.hash, totp.config.digits);
    let mut derive_totp_factor = derive_totp(totp_code as u32, None).unwrap();
    derive_totp_factor.id = Some("totp".to_string());
    derive_factors_map.insert("totp".to_string(), derive_totp_factor);

    // OOBA factor
    let policy_ooba_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "ooba").unwrap();
    let ooba_params = &policy_ooba_factor.params;
    let ciphertext = match ooba_params {
      crate::definitions::factor::FactorParams::OOBA(p) => hex::decode(&p.next).unwrap(),
      _ => panic!("Expected OOBA params"),
    };
    let decrypted = serde_json::from_slice::<Value>(
      &private_key.decrypt(Oaep::new::<Sha256>(), &ciphertext).unwrap(),
    )
    .unwrap();
    let code = decrypted["code"].as_str().unwrap();
    let mut derive_ooba_factor = derive_ooba(code).unwrap();
    derive_ooba_factor.id = Some("ooba".to_string());
    derive_factors_map.insert("ooba".to_string(), derive_ooba_factor);

    let derived_key = key(&setup_derived_key.policy, derive_factors_map, true, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.secret, setup_derived_key.secret);

    // derive again

    derive_factors_map = HashMap::new();

    // hotp factor
    let policy_hotp_factor = derived_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
    let hotp_params = &policy_hotp_factor.params;
    let counter = match hotp_params {
      crate::definitions::factor::FactorParams::HOTP(p) => p.counter,
      _ => panic!("Expected HOTP params"),
    };
    let correct_code =
      generate_otp_token(&hotp.config.secret[..20], counter, &hotp.config.hash, hotp.config.digits);
    let mut derive_hotp_factor = derive_hotp(correct_code as u32).unwrap();
    derive_hotp_factor.id = Some("hotp".to_string());
    derive_factors_map.insert("hotp".to_string(), derive_hotp_factor);

    // totp factor
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    let counter = time as u64 / (u64::from(totp.config.step) * 1000);
    let totp_code =
      generate_otp_token(&totp.config.secret[..20], counter, &totp.config.hash, totp.config.digits);
    let mut derive_totp_factor = derive_totp(totp_code as u32, None).unwrap();
    derive_totp_factor.id = Some("totp".to_string());
    derive_factors_map.insert("totp".to_string(), derive_totp_factor);

    // ooba factor
    let policy_ooba_factor = derived_key.policy.factors.iter().find(|f| f.id == "ooba").unwrap();
    let ooba_params = &policy_ooba_factor.params;
    let ciphertext = match ooba_params {
      crate::definitions::factor::FactorParams::OOBA(p) => hex::decode(&p.next).unwrap(),
      _ => panic!("Expected OOBA params"),
    };
    let decrypted = serde_json::from_slice::<Value>(
      &private_key.decrypt(Oaep::new::<Sha256>(), &ciphertext).unwrap(),
    )
    .unwrap();
    let code = decrypted["code"].as_str().unwrap();
    let mut derive_ooba_factor = derive_ooba(code).unwrap();
    derive_ooba_factor.id = Some("ooba".to_string());
    derive_factors_map.insert("ooba".to_string(), derive_ooba_factor);

    let derived_key2 = key(&derived_key.policy, derive_factors_map, true, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, derived_key2.key);
    assert_eq!(derived_key.secret, derived_key2.secret);
  }

  #[test]
  fn key_derivation_threshold_2_of_3() {
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

    let options = MFKDF2Options { threshold: Some(2), ..Default::default() };
    let setup_derived_key = setup::key(
      &[setup_password_factor.clone(), setup_hotp_factor.clone(), setup_totp_factor.clone()],
      options,
    )
    .unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // Password factor
    let mut derive_password_factor = derive_password("password123").unwrap();
    derive_password_factor.id = Some("pwd".to_string());
    derive_factors_map.insert("pwd".to_string(), derive_password_factor);

    // HOTP factor
    let policy_hotp_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
    let hotp_params = &policy_hotp_factor.params;
    let counter = match hotp_params {
      crate::definitions::factor::FactorParams::HOTP(p) => p.counter,
      _ => panic!("Expected HOTP params"),
    };
    let correct_code =
      generate_otp_token(&hotp.config.secret[..20], counter, &hotp.config.hash, hotp.config.digits);
    let mut derive_hotp_factor = derive_hotp(correct_code as u32).unwrap();
    derive_hotp_factor.id = Some("hotp".to_string());
    derive_factors_map.insert("hotp".to_string(), derive_hotp_factor);

    // We are only providing 2 out of 3 factors
    let derived_key = key(&setup_derived_key.policy, derive_factors_map, false, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.secret, setup_derived_key.secret);
  }

  #[test]
  fn key_derivation_threshold_3_of_5() {
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

    let (_, public_key) = keypair();
    let mut setup_ooba_factor = generate_ooba_setup_factor("ooba", &public_key);
    setup_ooba_factor.id = Some("ooba".to_string());

    let setup_factors = &[
      setup_password_factor.clone(),
      setup_hmac_factor.clone(),
      setup_hotp_factor.clone(),
      setup_totp_factor.clone(),
      setup_ooba_factor.clone(),
    ];
    let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
    let setup_derived_key = setup::key(setup_factors, options).unwrap();

    // Derivation phase
    let mut derive_factors_map = HashMap::new();

    // Password factor
    let mut derive_password_factor = derive_password("password123").unwrap();
    derive_password_factor.id = Some("pwd".to_string());
    derive_factors_map.insert("pwd".to_string(), derive_password_factor);

    // Hmac factor
    let policy_hmac_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hmac").unwrap();
    let params = &policy_hmac_factor.params;
    let challenge = match params {
      crate::definitions::factor::FactorParams::HmacSha1(p) => hex::decode(&p.challenge).unwrap(),
      _ => panic!("Expected HmacSha1 params"),
    };
    let secret = &hmac_setup.padded_secret[..20];
    let response = crate::crypto::hmacsha1(secret, &challenge);
    let mut derive_hmac_factor = derive_hmacsha1(response).unwrap();
    derive_hmac_factor.id = Some("hmac".to_string());
    derive_factors_map.insert("hmac".to_string(), derive_hmac_factor);

    // HOTP factor
    let policy_hotp_factor =
      setup_derived_key.policy.factors.iter().find(|f| f.id == "hotp").unwrap();
    let hotp_params = &policy_hotp_factor.params;
    let counter = match hotp_params {
      crate::definitions::factor::FactorParams::HOTP(p) => p.counter,
      _ => panic!("Expected HOTP params"),
    };
    let correct_code =
      generate_otp_token(&hotp.config.secret[..20], counter, &hotp.config.hash, hotp.config.digits);
    let mut derive_hotp_factor = derive_hotp(correct_code as u32).unwrap();
    derive_hotp_factor.id = Some("hotp".to_string());
    derive_factors_map.insert("hotp".to_string(), derive_hotp_factor);

    // We are only providing 3 out of 5 factors
    let derived_key = key(&setup_derived_key.policy, derive_factors_map, false, false).unwrap();

    // Assertions
    assert_eq!(derived_key.key, setup_derived_key.key);
    assert_eq!(derived_key.secret, setup_derived_key.secret);
  }

  #[test]
  fn key_derivation_shares() {
    // Setup phase
    let setup_factors = &[
      setup_password("password123", PasswordOptions { id: Some("pwd1".to_string()) }).unwrap(),
      setup_password("password456", PasswordOptions { id: Some("pwd2".to_string()) }).unwrap(),
      setup_password("password789", PasswordOptions { id: Some("pwd3".to_string()) }).unwrap(),
    ];
    let setup_derived_key =
      setup::key(setup_factors, MFKDF2Options { threshold: Some(2), ..Default::default() })
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

    let derived_key = key(&setup_derived_key.policy, derive_factors_map, true, false).unwrap();

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

    let derived_key = key(&setup_derived_key.policy, derive_factors_map, true, false).unwrap();

    // Assertions
    assert_eq!(derived_key.shares, setup_derived_key.shares);
  }

  #[test]
  fn key_derivation_persisted() -> Result<(), MFKDF2Error> {
    // Setup phase
    let setup_factors = &[
      setup_hotp(HOTPOptions::default())?,
      setup_password("password", PasswordOptions::default())?,
    ];
    let setup_derived_key = setup::key(setup_factors, MFKDF2Options::default())?;

    let hotp = setup_derived_key.persist_factor("hotp");

    let derive = derive::key(
      &setup_derived_key.policy,
      HashMap::from([
        ("hotp".to_string(), persisted(hotp)?),
        ("password".to_string(), derive_password("password")?),
      ]),
      true,
      false,
    )?;
    assert_eq!(derive.key, setup_derived_key.key);

    Ok(())
  }

  #[test]
  fn passkeys_liveness() -> Result<(), MFKDF2Error> {
    let mut prf = [0u8; 32];
    OsRng.fill_bytes(&mut prf);
    let setup_derived_key =
      setup::key(&[setup_passkey(prf, PasskeyOptions::default())?], MFKDF2Options::default())?;

    let derive = derive::key(
      &setup_derived_key.policy,
      HashMap::from([("passkey".to_string(), derive_passkey(prf)?)]),
      true,
      false,
    )?;
    assert_eq!(derive.key, setup_derived_key.key);

    Ok(())
  }

  #[test]
  fn passkeys_safety() -> Result<(), MFKDF2Error> {
    let mut prf = [0u8; 32];
    OsRng.fill_bytes(&mut prf);
    let setup_derived_key =
      setup::key(&[setup_passkey(prf, PasskeyOptions::default())?], MFKDF2Options::default())?;

    let mut prf2 = [0u8; 32];
    OsRng.fill_bytes(&mut prf2);

    let derive = derive::key(
      &setup_derived_key.policy,
      HashMap::from([("passkey".to_string(), derive_passkey(prf2)?)]),
      false,
      false,
    )?;
    assert_ne!(derive.key, setup_derived_key.key);

    Ok(())
  }
}
