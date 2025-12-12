//! # MFKDF2 Factor
//!
//!  A Factor represents an authentication primitive. Each factor has:
//!
//! - **Factor material**: the secret input (e.g., a password, TOTP secret, hardware key seed)
//! - **Public state**: non-secret metadata the factor needs to operate (e.g., counters,
//!   identifiers)
use serde::{Deserialize, Serialize};

use crate::{
  setup::factors::{hmacsha1, hotp, ooba, passkey, password, question, stack, totp, uuid},
  traits::Factor,
};

/// MFKDF2 factor instance.
///
/// In MFKDF2 protocol, a factor combines a secret piece of data (the factor material, often derived
/// from a password, hardware token response, TOTP code, etc.) with some public state stored on the
/// server. The job of a factor is to turn this dynamic user input into stable key material that can
/// be reused across multiple key derivations.
///
/// Each factor has two core operations:
/// - `setup`: creates an initial factor instance from a factor-specific configuration (e.g.,
///   password policy, TOTP parameters, hardware token IDs)
/// - `derive`: given a fresh user "witness" (e.g., the current password or OTP) and the current
///   public state, produces new factor material and updated public state for the next use.
///
/// # Example
///
/// ```rust
/// use mfkdf2::prelude::*;
///
/// // setup a password factor with id "pwd"
/// let setup = setup_password("password123", PasswordOptions { id: Some("pwd".to_string()) })?;
///
/// let p = match &setup.factor_type {
///   FactorType::Password(p) => p,
///   _ => panic!("Wrong factor type"),
/// };
/// assert_eq!(p.password, "password123");
///
/// // derive a key using the password factor
/// let derive = derive_password("password123")?;
/// let p = match &derive.factor_type {
///   FactorType::Password(p) => p,
///   _ => panic!("Wrong factor type"),
/// };
/// assert_eq!(p.password, "password123");
/// assert_eq!(derive.data(), "password123".as_bytes());
/// # MFKDF2Result::Ok(())
/// ```
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
pub struct MFKDF2Factor {
  /// Optional application-defined identifier for the factor.
  pub id:          Option<String>,
  /// Concrete factor implementation (password, TOTP, passkey, etc.).
  pub factor_type: FactorType,
  /// Optional estimated real [`MFKDF2Entropy`](`crate::definitions::MFKDF2Entropy`) of this factor
  /// instance (in bits).
  pub entropy:     Option<f64>,
}

impl MFKDF2Factor {
  /// Returns the type of the factor.
  pub fn kind(&self) -> &'static str { self.factor_type.kind() }

  /// Returns the bytes of the factor material.
  pub fn data(&self) -> Vec<u8> { self.factor_type.bytes() }
}

impl std::fmt::Debug for MFKDF2Factor {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("MFKDF2Factor")
      .field("kind", &self.kind())
      .field("id", &self.id)
      .field("data", &self.factor_type)
      .field("params", &"<function>")
      .field("entropy", &self.entropy)
      .field("output", &"<future>")
      .finish()
  }
}

/// Factor type enum representing all supported authentication factors.
///
/// Each variant corresponds to a concrete factor type (such as password, TOTP, passkey,
/// etc.). Every factor implement the `FactorMetadata`, `FactorSetup`, and `FactorDerive` traits,
/// which define the common interface for factor management, setup, and derivation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
pub enum FactorType {
  /// [`password::Password`] factor.
  Password(password::Password),
  /// [`hotp::HOTP`] factor.
  HOTP(hotp::HOTP),
  /// [`question::Question`] factor.
  Question(question::Question),
  /// [`uuid::UUIDFactor`] factor.
  UUID(uuid::UUIDFactor),
  /// [`hmacsha1::HmacSha1`] factor.
  HmacSha1(hmacsha1::HmacSha1),
  /// [`totp::TOTP`] factor.
  TOTP(totp::TOTP),
  /// [`ooba::Ooba`] factor.
  OOBA(ooba::Ooba),
  /// [`passkey::Passkey`] factor.
  Passkey(passkey::Passkey),
  /// [`stack::Stack`] factor.
  Stack(stack::Stack),
  /// [Persisted](`crate::derive::factors::persisted::Persisted`) factor.
  Persisted(crate::derive::factors::persisted::Persisted),
}

/// Public, serializable parameters for each supported authentication factor.
/// Each variant corresponds to its respective factor type's parameter struct.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
pub enum FactorParams {
  /// Parameters for the [`password::Password`] factor.
  Password(password::PasswordParams),
  /// Parameters for the [`hotp::HOTP`] factor.
  HOTP(hotp::HOTPParams),
  /// Parameters for the [`question::Question`] factor.
  Question(question::QuestionParams),
  /// Parameters for the [`uuid::UUIDFactor`] factor.
  UUID(uuid::UUIDFactorParams),
  /// Parameters for the [`hmacsha1::HmacSha1`] factor.
  HmacSha1(hmacsha1::HmacSha1Params),
  /// Parameters for the [`totp::TOTP`] factor.
  TOTP(totp::TOTPParams),
  /// Parameters for the [`ooba::Ooba`] factor.
  OOBA(ooba::OobaParams),
  /// Parameters for the [`passkey::Passkey`] factor.
  Passkey(passkey::PasskeyParams),
  /// Parameters for the [`stack::Stack`] factor.
  Stack(stack::StackParams),
  /// Parameters for the [`persisted::Persisted`](`crate::derive::factors::persisted::Persisted`)
  /// derived factor.
  Persisted(crate::derive::factors::persisted::PersistedParams),
}

impl FactorType {
  pub(crate) fn bytes(&self) -> Vec<u8> {
    factor_dispatch_method!(self, bytes() => {
      Password, HOTP, Question, UUID, HmacSha1, TOTP, OOBA, Passkey, Stack, Persisted
    })
  }

  pub(crate) fn kind(&self) -> &'static str {
    factor_dispatch_method!(self, kind() => {
      Password, HOTP, Question, UUID, HmacSha1, TOTP, OOBA, Passkey, Stack, Persisted
    })
  }
}
