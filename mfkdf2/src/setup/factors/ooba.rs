//! Out‑of‑band (OOBA) challenge factor setup.
//!
//! This factor is designed for flows where the user confirms a login or recovery
//! action on a **separate channel** (for example, push notification, e‑mail link,
//! or SMS) using a short alphanumeric code. Instead of treating the OOBA channel
//! itself as a secret, MFKDF2 derives factor material from a random 32‑byte target
//! and uses the channel only to transport a fresh one‑time code and an encrypted
//! payload.
//!
//! Conceptually:
//! - an OOBA service holds a public key pkₒ for the delivery channel, such as the recipient’s
//!   S/MIME key or an SMS gateway RSA key
//! - during **setup**, the library samples a fixed integer targetₒ and an initial OOBA code otpₒ,₀
//!   of `d` digits, both chosen uniformly from the range [0, 10ᵈ)
//! - the modular difference offsetₒ,₀ = (targetₒ − otpₒ,₀) % 10ᵈ is stored along with an encrypted
//!   code ciphertext ctₒ,₀ under pkₒ
//! - the public parameters βₒ,₀ embed `(d, pkₒ, offsetₒ,₀, ctₒ,₀)` into the policy
//!
//! During derive, the user receives a new OOBA challenge on the secondary channel
//! and submits the corresponding code Wₒ,ᵢ = otpₒ,ᵢ to the application. Using the
//! stored offset for that step, the factor reconstructs a stable secret
//! σₒ = (offsetₒ,ᵢ + Wₒ,ᵢ) % 10ᵈ and derives the same key material as in setup,
//! while at the same time encrypting the next challenge payload for the following
//! login. Even if the OOBA channel is only partially trusted, the resulting factor
//! material remains uniformly distributed and provides the same information‑theoretic
//! guarantees as the HOTP and TOTP constructions.
use aes::Aes256;
use base64::{Engine, engine::general_purpose};
use cbc::Encryptor;
use cipher::KeyIvInit;
use jsonwebtoken::jwk::Jwk;
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{
  crypto::{encrypt_cbc, hkdf_sha256_with_info},
  definitions::{FactorType, Key, MFKDF2Factor, factor::FactorMetadata},
  error::{MFKDF2Error, MFKDF2Result},
  rng::GlobalRng,
  setup::FactorSetup,
};

/// Generates a random alphanumeric string of the given length.
#[inline]
#[must_use]
pub fn generate_alphanumeric_characters(length: u32) -> String {
  (0..length)
    .map(|_| {
      let n: u8 = crate::rng::gen_range_u8(36); // 0–35
      char::from_digit(u32::from(n), 36).unwrap() // base-36 => 0–9, a–z
    })
    .collect()
}

/// Wrapper for the RSA public key used to encrypt the next OOBA payload
pub struct OobaPublicKey(pub RsaPublicKey);

/// Options for configuring an OOBA factor
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OobaOptions {
  /// Optional application-defined identifier for the factor, defaults to `"ooba"` and must be
  /// non-empty if provided
  pub id:     Option<String>,
  /// Number of alphanumeric characters in the OOBA code in the range 1–32, otherwise
  /// [`MFKDF2Error::InvalidOobaLength`] is returned
  pub length: Option<u8>,
  /// RSA public key as a JWK used to encrypt the next OOBA payload; must be an RSA key or
  /// [`MFKDF2Error::InvalidOobaKey`] is returned
  pub key:    Option<Jwk>,
  /// Arbitrary JSON metadata re‑encrypted and sent to the OOBA service such as user id, device id,
  /// or display message
  pub params: Option<Value>,
}

impl Default for OobaOptions {
  fn default() -> Self {
    Self { id: Some("ooba".to_string()), length: Some(6), key: None, params: None }
  }
}

/// OOBA factor state
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ooba {
  /// Randomly generated 32‑byte target used as the factor’s underlying secret
  // TODO (@lonerapier): use uniffi custom type
  pub target: Vec<u8>,
  /// Number of alphanumeric characters in the OOBA code bound to this factor
  pub length: u8,
  /// OOBA factor material as the last issued code value
  pub code:   String,
  /// RSA public key used to encrypt the next OOBA payload
  pub jwk:    Option<Jwk>,
  /// Arbitrary JSON metadata re‑encrypted and sent to the OOBA service such as user id, device id,
  /// or display message
  pub params: Value,
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Ooba {
  fn zeroize(&mut self) {
    self.target.zeroize();
    self.code.zeroize();
  }
}
impl TryFrom<&Jwk> for OobaPublicKey {
  type Error = MFKDF2Error;

  fn try_from(key: &Jwk) -> Result<Self, Self::Error> {
    let n_str = match &key.algorithm {
      jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa_params) => &rsa_params.n,
      _ => return Err(MFKDF2Error::InvalidOobaKey),
    };
    let e_str = match &key.algorithm {
      jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa_params) => &rsa_params.e,
      _ => return Err(MFKDF2Error::InvalidOobaKey),
    };
    let n = rsa::BigUint::from_bytes_be(
      &base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n_str)
        .map_err(MFKDF2Error::Base64Decode)?,
    );
    let e = rsa::BigUint::from_bytes_be(
      &base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(e_str)
        .map_err(MFKDF2Error::Base64Decode)?,
    );
    Ok(OobaPublicKey(RsaPublicKey::new(n, e).map_err(|_| MFKDF2Error::InvalidOobaKey)?))
  }
}

impl FactorMetadata for Ooba {
  fn kind(&self) -> String { "ooba".to_string() }

  fn bytes(&self) -> Vec<u8> { self.target.clone() }
}

impl FactorSetup for Ooba {
  type Output = Value;
  type Params = Value;

  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> {
    let code = generate_alphanumeric_characters(self.length.into()).to_uppercase();

    let prev_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);

    let key = cipher::Key::<Encryptor<Aes256>>::from(prev_key);
    let iv = Encryptor::<Aes256>::generate_iv(&mut GlobalRng);
    let pad = encrypt_cbc::<Aes256>(&self.target, &key, &iv)?;

    // store the secret code for the next derivation
    let mut params = self.params.clone();
    params["code"] = json!(code);
    params["iv"] = json!(general_purpose::STANDARD.encode(iv));

    // store the iv in public params for the next derivation
    let mut pub_params = self.params.clone();
    pub_params["iv"] = json!(general_purpose::STANDARD.encode(iv));

    // encrypt the params and store the ciphertext for the next derivation
    let plaintext = serde_json::to_vec(&params)?;
    let key = OobaPublicKey::try_from(self.jwk.as_ref().ok_or(MFKDF2Error::MissingOobaKey)?)?;
    let ciphertext = key.0.encrypt(&mut OsRng, Oaep::new::<Sha256>(), &plaintext)?;

    Ok(json!({
        "length": self.length,
        "key": self.jwk,
        "params": pub_params,
        "next": hex::encode(ciphertext),
        "pad": general_purpose::STANDARD.encode(pad),
    }))
  }
}

/// Creates an OOBA factor from the given options
///
/// This helper validates the configuration, generates a random 32‑byte target,
/// and returns an [`MFKDF2Factor`] whose entropy estimate depends on the number
/// of alphanumeric characters in the code. During setup, `params()` generates a
/// fresh user‑visible OOBA code, derives a one‑time key from that code to pad
/// the internal target, and produces an RSA‑encrypted payload embedding the
/// application’s `params` plus the code for delivery through the out‑of‑band
/// channel.
///
/// # Errors
/// - [`MFKDF2Error::MissingFactorId`] if `id` is provided but empty
/// - [`MFKDF2Error::InvalidOobaLength`] if `length` is `0` or greater than `32`
/// - [`MFKDF2Error::MissingOobaKey`] if no RSA JWK is provided
/// - [`MFKDF2Error::InvalidOobaKey`] if the provided JWK is not an RSA key
///
/// # Example
///
/// ```rust
/// use mfkdf2::setup::factors::ooba::{ooba, OobaOptions};
/// use jsonwebtoken::jwk::Jwk;
/// # let jwk: Jwk = serde_json::from_str(r#"{"kty":"RSA","n":"...","e":"AQAB"}"#).unwrap();
/// let options = OobaOptions {
///   id: Some("push-ooba".into()),
///   length: Some(8),
///   key: Some(jwk),
///   params: Some(serde_json::json!({"channel": "push", "device": "phone-1"})),
/// };
/// let factor = ooba(options)?;
/// assert_eq!(factor.id.as_deref(), Some("push-ooba"));
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
///
/// Invalid length
///
/// ```rust
/// use mfkdf2::setup::factors::ooba::{ooba, OobaOptions};
/// use jsonwebtoken::jwk::Jwk;
/// # let jwk: Jwk = serde_json::from_str(r#"{"kty":"RSA","alg":"RSA-OAEP-256","n":"AA","e":"AQAB"}"#).unwrap();
/// # use mfkdf2::error::MFKDF2Error;
/// let options = OobaOptions {
///   length: Some(40), // outside the allowed 1–32 range
///   key: Some(jwk),
///   ..Default::default()
/// };
/// let result = ooba(options);
/// assert!(matches!(result, Err(MFKDF2Error::InvalidOobaLength)));
/// # Ok::<(), MFKDF2Error>(())
/// ```
pub fn ooba(mut options: OobaOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let length = options.length.unwrap_or(6);
  if length == 0 || length > 32 {
    return Err(MFKDF2Error::InvalidOobaLength);
  }

  let params = options.params.take().unwrap_or_default();
  let key = options.key.take().ok_or(MFKDF2Error::MissingOobaKey)?;
  // verify that key is rsa public key
  if !matches!(key.algorithm, jsonwebtoken::jwk::AlgorithmParameters::RSA(_)) {
    return Err(MFKDF2Error::InvalidOobaKey);
  }

  // Generate 32-byte random target (the factor's data)
  let mut target = [0u8; 32];
  crate::rng::fill_bytes(&mut target);

  Ok(MFKDF2Factor {
    id:          Some(options.id.take().unwrap_or("ooba".to_string())),
    factor_type: FactorType::OOBA(Ooba {
      target: target.to_vec(),
      length,
      code: String::new(),
      jwk: Some(key),
      params,
    }),
    entropy:     Some((36_f64.powf(f64::from(length))).log2()),
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn setup_ooba(options: OobaOptions) -> MFKDF2Result<MFKDF2Factor> { ooba(options) }

#[cfg(test)]
mod tests {
  use rsa::{RsaPrivateKey, traits::PublicKeyParts};

  use super::*;

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

  fn mock_construction(key: &RsaPublicKey) -> MFKDF2Factor {
    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: Some(8),
      key:    Some(jwk(key)),
      params: Some(json!({"foo":"bar"})),
    };

    let result = ooba(options);
    assert!(result.is_ok());

    result.unwrap()
  }

  #[test]
  fn construction() {
    let (_, public_key) = keypair();

    let factor = mock_construction(&public_key);

    assert_eq!(factor.id, Some("test".to_string()));

    assert!(matches!(factor.factor_type, FactorType::OOBA(_)));
    if let FactorType::OOBA(ooba_factor) = factor.factor_type {
      assert_eq!(ooba_factor.length, 8);
      assert_eq!(ooba_factor.jwk, Some(jwk(&public_key)));
      assert_eq!(ooba_factor.params, json!({"foo":"bar"}));
      assert_eq!(ooba_factor.target.len(), 32);
    }
  }

  #[test]
  fn empty_id() {
    let (_, public_key) = keypair();

    let options = OobaOptions {
      id:     Some("".to_string()),
      length: Some(6),
      key:    Some(jwk(&public_key)),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::MissingFactorId)));
  }

  #[test]
  fn zero_length() {
    let (_, public_key) = keypair();

    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: Some(0),
      key:    Some(jwk(&public_key)),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidOobaLength)));
  }

  #[test]
  fn large_length() {
    let (_, public_key) = keypair();

    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: Some(33),
      key:    Some(jwk(&public_key)),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidOobaLength)));
  }

  #[test]
  fn missing_key() {
    let options =
      OobaOptions { id: Some("test".to_string()), length: Some(6), key: None, params: None };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::MissingOobaKey)));
  }

  #[test]
  fn not_rsa_key() {
    const TEST_EC_JWK: &str = r#"{
      "kty": "EC",
      "crv": "P-256",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvlogunL7_vC1Gja-9XRUPKnsI"
    }"#;

    let options = OobaOptions {
      id:     Some("test".to_string()),
      length: Some(6),
      key:    Some(serde_json::from_str(TEST_EC_JWK).unwrap()),
      params: None,
    };
    let result = ooba(options);
    assert!(matches!(result, Err(MFKDF2Error::InvalidOobaKey)));
  }

  #[test]
  fn params() {
    let (private_key, public_key) = keypair();
    let factor = mock_construction(&public_key);

    let ooba: Ooba = match factor.factor_type {
      FactorType::OOBA(ooba) => ooba,
      _ => panic!("Factor type should be Ooba"),
    };

    let params = ooba.params([0u8; 32].into()).unwrap();
    assert!(params.is_object());

    let ciphertext = hex::decode(params["next"].as_str().unwrap()).unwrap();
    let decrypted = serde_json::from_slice::<Value>(
      &private_key.decrypt(Oaep::new::<Sha256>(), &ciphertext).unwrap(),
    )
    .unwrap();
    let code = decrypted["code"].as_str().unwrap();
    let iv = general_purpose::STANDARD.decode(decrypted["iv"].as_str().unwrap()).unwrap();

    let prev_key = hkdf_sha256_with_info(code.as_bytes(), &[], &[]);
    let pad = general_purpose::STANDARD.decode(params["pad"].as_str().unwrap()).unwrap();
    let key = cipher::Key::<cbc::Decryptor<Aes256>>::from(prev_key);
    let iv = cipher::Iv::<cbc::Decryptor<Aes256>>::from_iter(iv);
    let target = crate::crypto::decrypt_cbc::<Aes256>(&pad, &key, &iv).unwrap();

    assert_eq!(ooba.target, target);
  }

  #[test]
  fn output() {
    let (_, public_key) = keypair();
    let factor = mock_construction(&public_key);
    let output = factor.factor_type.output();
    assert_eq!(output, json!({}));
  }
}
