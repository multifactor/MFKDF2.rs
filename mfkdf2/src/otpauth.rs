//! OTP Auth URL generation for TOTP and HOTP credentials compatible with Google Authenticator and
//! other OTP authenticators.
use std::fmt::Write;

use data_encoding::{BASE32_NOPAD, HEXLOWER};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::MFKDF2Error;

/// An OATH credential can be a TOTP (Time-based One-time Password) or a HOTP (HMAC-based One-time
/// Password).
#[derive(Debug, Clone, Copy)]
pub enum Kind {
  /// TOTP (Time-based One-time Password)
  Totp,
  /// HOTP (HMAC-based One-time Password)
  Hotp,
}

impl std::fmt::Display for Kind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", match self {
      Kind::Totp => "totp",
      Kind::Hotp => "hotp",
    })
  }
}

/// Encoding for the secret used.
#[derive(Debug, Clone)]
pub enum Encoding {
  /// Treat `secret` as raw ASCII bytes (e.g., "mysecret")
  Ascii,
  /// Treat `secret` as Base32 (A–Z2–7, spaces ignored)
  Base32,
  /// Treat `secret` as hex (lower/upper both OK, spaces ignored)
  Hex,
}

/// The hash algorithm used by the credential
#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashAlgorithm {
  /// SHA-1
  #[serde(rename = "sha1")]
  Sha1,
  /// SHA-256
  #[serde(rename = "sha256")]
  Sha256,
  /// SHA-512
  #[serde(rename = "sha512")]
  Sha512,
}

impl std::fmt::Display for HashAlgorithm {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", match self {
      HashAlgorithm::Sha1 => "sha1",
      HashAlgorithm::Sha256 => "sha256",
      HashAlgorithm::Sha512 => "sha512",
    })
  }
}

/// Options for generating an OTP Auth URI
#[derive(Debug, Clone)]
pub struct OtpAuthUrlOptions {
  /// The shared secret is the secret key that is used to generate the OTP. The format depends on
  /// the encoding specified in the [`Encoding`] field
  pub secret:    String,
  /// The label is used to identify which account a credential is associated with. It also serves
  /// as the unique identifier for the credential itself
  pub label:     String,
  /// Credential type, either [`Kind::Totp`] or [`Kind::Hotp`]
  pub kind:      Option<Kind>,
  /// The issuer parameter is an optional string value indicating the provider or service the
  /// credential is associated with
  pub issuer:    Option<String>,
  /// The number of digits in the OTP. Allowed values are 6, 7, and 8. Defaults to 6
  pub digits:    Option<u32>,
  /// The optional counter parameter is required when provisioning HOTP credentials. It will set
  /// the initial counter value
  pub counter:   Option<u64>,
  /// The period parameter defines a validity period in seconds for the TOTP code. It is only
  /// applicable for TOTP credentials and defaults to 30 seconds
  pub period:    Option<u64>,
  /// The encoding of the secret
  pub encoding:  Option<Encoding>,
  /// The hash algorithm to use for the credential
  pub algorithm: Option<HashAlgorithm>,
}

/// Convert an input secret (with a declared encoding) into Base32 (no padding),
/// removing spaces and normalizing case where needed.
fn secret_to_base32_no_pad(secret: &str, enc: &Encoding) -> Result<String, String> {
  match enc {
    Encoding::Ascii => {
      // Interpret characters literally as bytes, then Base32 encode
      Ok(BASE32_NOPAD.encode(secret.as_bytes()))
    },
    Encoding::Base32 => {
      // Strip whitespace and normalize to upper-case; validate by decode+re-encode
      let clean: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
      let decoded = data_encoding::BASE32_NOPAD
        .decode(clean.as_bytes())
        .map_err(|_| "Invalid Base32 secret".to_string())?;
      Ok(BASE32_NOPAD.encode(&decoded))
    },
    Encoding::Hex => {
      let clean: String =
        secret.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
      let decoded =
        HEXLOWER.decode(clean.as_bytes()).map_err(|_| "Invalid hex secret".to_string())?;
      Ok(BASE32_NOPAD.encode(&decoded))
    },
  }
}

/// Generates an OTP Auth URI compatible with Google Authenticator and other OTP authenticators.
/// The otpauth:// URI scheme is used to encode one-time password (OTP) secrets for use with
/// authenticator applications, typically encoded in QR codes for easy provisioning.
///
/// # Arguments
///
/// * `options` - The options for generating the OTP Auth URI.
///
/// # Returns
///
/// A string representing the OTP Auth URI.
///
/// # Errors
///
/// Returns an error if the secret is invalid or the options are missing required fields.
pub fn otpauth_url(options: &OtpAuthUrlOptions) -> Result<String, MFKDF2Error> {
  let enc = options.encoding.as_ref().unwrap_or(&Encoding::Ascii);
  let alg =
    options.algorithm.as_ref().unwrap_or(&HashAlgorithm::Sha1).to_string().to_ascii_uppercase();
  let digits = options.digits.unwrap_or(6);
  let period = options.period.unwrap_or(30);
  let kind = options.kind.unwrap_or(Kind::Totp);

  let secret = secret_to_base32_no_pad(&options.secret.clone(), enc)
    .map_err(|_| MFKDF2Error::InvalidSecret)?;
  let label = options.label.clone();
  let issuer = options.issuer.clone();

  let mut url = format!("otpauth://{kind}/{label}?secret={secret}");

  if let Some(issuer) = issuer {
    write!(&mut url, "&issuer={issuer}")?;
  }

  write!(&mut url, "&algorithm={alg}&digits={digits}")?;

  if matches!(kind, Kind::Totp) {
    write!(&mut url, "&period={period}")?;
  }
  // TODO (@lonerapier): speakeasy doesn't add counter to the url for hotp
  // else {
  //   let counter = options.counter.ok_or(MFKDF2Error::MissingOtpAuthUrlOptions("counter"))?;
  //   url.push_str(&format!("&counter={counter}"));
  // }

  Ok(url)
}

/// Generate a counter-based one-time token of the given length.
///
/// # Arguments
///
/// * `secret` - The shared secret is the secret key that is used to generate the OTP
/// * `counter` - The counter value to use for the OTP.
/// * `hash` - The hash algorithm to use for the OTP.
/// * `digits` - The number of digits in the OTP.
pub fn generate_otp_token(secret: &[u8], counter: u64, hash: &HashAlgorithm, digits: u32) -> u32 {
  let counter_bytes = counter.to_be_bytes();

  let digest = match hash {
    HashAlgorithm::Sha1 => {
      let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
    HashAlgorithm::Sha256 => {
      let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
    HashAlgorithm::Sha512 => {
      let mut mac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
      mac.update(&counter_bytes);
      mac.finalize().into_bytes().to_vec()
    },
  };

  // Dynamic truncation as per RFC 4226
  let offset = (digest[digest.len() - 1] & 0xf) as usize;
  let code = u32::from_be_bytes([
    digest[offset] & 0x7f,
    digest[offset + 1],
    digest[offset + 2],
    digest[offset + 3],
  ]);

  code % 10_u32.pow(digits)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn otpauth_url_totp() {
    let options = OtpAuthUrlOptions {
      secret:    "mysecret".to_string(),
      label:     "mylabel".to_string(),
      kind:      Some(Kind::Totp),
      counter:   Some(1),
      issuer:    Some("myissuer".to_string()),
      digits:    Some(6),
      period:    Some(30),
      encoding:  Some(Encoding::Ascii),
      algorithm: Some(HashAlgorithm::Sha1),
    };

    let url = otpauth_url(&options).unwrap();
    assert_eq!(
      url,
      "otpauth://totp/mylabel?secret=NV4XGZLDOJSXI&issuer=myissuer&algorithm=SHA1&digits=6&\
       period=30"
    );
  }

  #[test]
  fn otpauth_url_hotp() {
    let options = OtpAuthUrlOptions {
      secret:    "mysecret".to_string(),
      label:     "mylabel".to_string(),
      kind:      Some(Kind::Hotp),
      counter:   Some(1),
      issuer:    Some("myissuer".to_string()),
      digits:    Some(6),
      period:    None,
      encoding:  Some(Encoding::Ascii),
      algorithm: Some(HashAlgorithm::Sha1),
    };

    let url = otpauth_url(&options).unwrap();
    assert_eq!(
      url,
      "otpauth://hotp/mylabel?secret=NV4XGZLDOJSXI&issuer=myissuer&algorithm=SHA1&digits=6"
    );
  }

  #[test]
  fn otpauth_url_base32() {
    let options = OtpAuthUrlOptions {
      secret:    BASE32_NOPAD.encode(b"mysecret"),
      label:     "mylabel".to_string(),
      kind:      Some(Kind::Totp),
      counter:   Some(1),
      issuer:    Some("myissuer".to_string()),
      digits:    Some(6),
      period:    Some(30),
      encoding:  Some(Encoding::Base32),
      algorithm: Some(HashAlgorithm::Sha1),
    };

    let url = otpauth_url(&options).unwrap();
    assert_eq!(
      url,
      "otpauth://totp/mylabel?secret=NV4XGZLDOJSXI&issuer=myissuer&algorithm=SHA1&digits=6&\
       period=30"
    );
  }

  #[test]
  fn otpauth_url_hex() {
    let options = OtpAuthUrlOptions {
      secret:    hex::encode("mysecret"),
      label:     "mylabel".to_string(),
      kind:      Some(Kind::Totp),
      counter:   Some(1),
      issuer:    Some("myissuer".to_string()),
      digits:    Some(6),
      period:    Some(30),
      encoding:  Some(Encoding::Hex),
      algorithm: Some(HashAlgorithm::Sha1),
    };

    let url = otpauth_url(&options).unwrap();
    assert_eq!(
      url,
      "otpauth://totp/mylabel?secret=NV4XGZLDOJSXI&issuer=myissuer&algorithm=SHA1&digits=6&\
       period=30"
    );
  }

  #[test]
  fn test_generate_hotp_code() {
    let secret = b"hello world";
    let counter = 1;
    let hash = HashAlgorithm::Sha1;
    let digits = 6;

    let code = generate_otp_token(secret, counter, &hash, digits);
    assert!(code < 10_u32.pow(digits));

    // Same inputs should produce same output
    let code2 = generate_otp_token(secret, counter, &hash, digits);
    assert_eq!(code, code2);

    // Different counter should produce different output
    let code3 = generate_otp_token(secret, counter + 1, &hash, digits);
    assert_ne!(code, code3);
  }
}
