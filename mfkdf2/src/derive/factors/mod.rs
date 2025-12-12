//! Factor construction derive phase
//!
//! This module constructs [`MFKDF2Factor`](`crate::definitions::MFKDF2Factor`) witnesses Wᵢⱼ for
//! the derive phase corresponding to the setup factors defined in [`mod@crate::setup::factors`].
//! Each helper takes respective factor secret (such as a password, OTP code, UUID, or passkey
//! secret) plus any derive-specific options and constructs a
//! [`MFKDF2Factor`](`crate::definitions::MFKDF2Factor`) that is used in `KeyDerive` derivation.
//!
//! During the [`KeyDerive`](`crate::derive::key::key`) phase, these factors combine with the public
//! policy state βᵢ to reconstruct the underlying static source material κⱼ and ultimately recover
//! the master secret `M` and next derived key state βᵢ₊₁.
//!
//! **Note:** Factor setup/derive individually are not intended to be used in isolation, but are
//! composed through [`setup::key`](`crate::setup::key`) (Setup) and
//! [`derive::key`](`crate::derive::key::key`) (Derive), respectively, where factors supply witness
//! material for the overall multi‑factor policy.
mod hmacsha1;
mod hotp;
mod ooba;
mod passkey;
mod password;
pub mod persisted;
mod question;
mod stack;
pub mod totp;
mod uuid;

pub use hmacsha1::hmacsha1;
pub use hotp::hotp;
pub use ooba::ooba;
pub use passkey::passkey;
pub use password::password;
pub use persisted::persisted;
pub use question::question;
pub use stack::stack;
pub use totp::totp;
pub use uuid::uuid;

use crate::{
  definitions::{FactorType, Key, factor::FactorParams},
  derive::FactorDerive,
  error::MFKDF2Result,
};

pub(crate) struct FactorDeriveCtx<'a>(pub(crate) &'a FactorType);

impl FactorType {
  /// Returns the derive implementation for the factor type.
  pub(crate) fn derive(&self) -> FactorDeriveCtx<'_> { FactorDeriveCtx(self) }

  /// Include parameters for the factor during derivation.
  pub(crate) fn include_params(&mut self, params: FactorParams) -> MFKDF2Result<()> {
    factor_dispatch_include_params!(self, params => {
      Password, HOTP, Question, UUID, HmacSha1, TOTP, OOBA, Passkey, Stack, Persisted
    })
  }
}

impl FactorDeriveCtx<'_> {
  /// Get parameters for the factor during derivation.
  pub(crate) fn params(&self, key: Key) -> MFKDF2Result<FactorParams> {
    factor_dispatch_params!(self.0, params(key) => {
      Password => Password,
      HOTP => HOTP,
      Question => Question,
      UUID => UUID,
      HmacSha1 => HmacSha1,
      TOTP => TOTP,
      OOBA => OOBA,
      Passkey => Passkey,
      Stack => Stack,
      Persisted => Persisted,
    })
  }

  /// Get output for the factor during derivation.
  pub(crate) fn output(&self) -> serde_json::Value {
    factor_dispatch_output!(self.0, output() => {
      Password, HOTP, Question, UUID, HmacSha1, TOTP, OOBA, Passkey, Stack, Persisted
    })
  }
}
