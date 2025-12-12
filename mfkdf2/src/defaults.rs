//! Default values for factor configurations.
//!
//! This module provides a single source of truth for all default values used across
//! factor setup. This eliminates duplication and ensures consistency.

use crate::otpauth::HashAlgorithm;

/// Default values for HOTP factor configuration.
pub(crate) mod hotp {
  use super::*;

  /// Default factor identifier for HOTP.
  pub(crate) const ID: &str = "hotp";

  /// Default number of digits in HOTP codes (6-8 are valid).
  pub(crate) const DIGITS: u32 = 6;

  /// Default hash algorithm for HOTP generation.
  pub(crate) const HASH: HashAlgorithm = HashAlgorithm::Sha1;

  /// Default issuer name for HOTP credentials.
  pub(crate) const ISSUER: &str = "MFKDF";

  /// Default label for HOTP credentials.
  pub(crate) const LABEL: &str = "mfkdf.com";

  /// Default HOTP counter value.
  pub(crate) const COUNTER: u64 = 1;
}

/// Default values for TOTP factor configuration.
pub(crate) mod totp {
  use super::*;

  /// Default factor identifier for TOTP.
  pub(crate) const ID: &str = "totp";

  /// Default number of digits in TOTP codes (6-8 are valid).
  pub(crate) const DIGITS: u32 = 6;

  /// Default hash algorithm for TOTP generation.
  pub(crate) const HASH: HashAlgorithm = HashAlgorithm::Sha1;

  /// Default issuer name for TOTP credentials.
  pub(crate) const ISSUER: &str = "MFKDF";

  /// Default label for TOTP credentials.
  pub(crate) const LABEL: &str = "mfkdf.com";

  /// Default TOTP step size in seconds (the "period").
  pub(crate) const STEP: u32 = 30;

  /// Default number of TOTP steps for which offsets are precomputed.
  /// This is sized for long-lived offline use (approximately 1 year).
  pub(crate) const WINDOW: u32 = 87600;
}

/// Default values for Password factor configuration.
pub(crate) mod password {
  /// Default factor identifier for Password.
  pub(crate) const ID: &str = "password";
}

/// Default values for UUID factor configuration.
pub(crate) mod uuid {
  /// Default factor identifier for UUID.
  pub(crate) const ID: &str = "uuid";

  /// Default entropy for UUID factor (122 bits for UUID v4).
  pub(crate) const ENTROPY: f64 = 122.0;
}

/// Default values for Question factor configuration.
pub(crate) mod question {
  /// Default factor identifier for Question.
  pub(crate) const ID: &str = "question";
}

/// Default values for OOBA factor configuration.
pub(crate) mod ooba {
  /// Default factor identifier for OOBA.
  pub(crate) const ID: &str = "ooba";

  /// Default number of alphanumeric characters in OOBA codes (1-32 are valid).
  pub(crate) const LENGTH: u8 = 6;
}

/// Default values for Passkey factor configuration.
pub(crate) mod passkey {
  /// Default factor identifier for Passkey.
  pub(crate) const ID: &str = "passkey";

  /// Default entropy for Passkey factor (256 bits for 32-byte secret).
  pub(crate) const ENTROPY: f64 = 256.0;
}

/// Default values for HMACSHA1 factor configuration.
pub(crate) mod hmacsha1 {
  /// Default factor identifier for HMACSHA1.
  pub(crate) const ID: &str = "hmacsha1";

  /// Default entropy for HMACSHA1 factor (160 bits for 20-byte secret).
  pub(crate) const ENTROPY: f64 = 160.0;
}

/// Default values for Stack factor configuration.
pub(crate) mod stack {
  /// Default factor identifier for Stack.
  pub(crate) const ID: &str = "stack";
}

/// Default values for Persisted factor configuration.
pub(crate) mod persisted {
  /// Default factor identifier for Persisted.
  pub(crate) const ID: &str = "persisted";
}
