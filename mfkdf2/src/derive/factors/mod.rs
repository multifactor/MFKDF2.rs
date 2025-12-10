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
  definitions::{
    FactorType, Key,
    factor::{FactorMetadata, FactorOutput, FactorParams},
  },
  derive::FactorDerive,
  error::MFKDF2Result,
};

pub(crate) struct FactorDeriveCtx<'a>(pub(crate) &'a FactorType);

impl FactorType {
  /// Returns the setup implementation for the factor type.
  pub(crate) fn derive(&self) -> FactorDeriveCtx<'_> { FactorDeriveCtx(self) }

  /// Include parameters for the factor during derivation.
  pub(crate) fn include_params(&mut self, params: FactorParams) -> MFKDF2Result<()> {
    match (self, params) {
      (FactorType::Password(password), FactorParams::Password(p)) => password.include_params(p),
      (FactorType::HOTP(hotp), FactorParams::HOTP(p)) => hotp.include_params(p),
      (FactorType::Question(question), FactorParams::Question(p)) => question.include_params(p),
      (FactorType::UUID(uuid), FactorParams::UUID(p)) => uuid.include_params(p),
      (FactorType::HmacSha1(hmacsha1), FactorParams::HmacSha1(p)) => hmacsha1.include_params(p),
      (FactorType::TOTP(totp), FactorParams::TOTP(p)) => totp.include_params(p),
      (FactorType::OOBA(ooba), FactorParams::OOBA(p)) => ooba.include_params(p),
      (FactorType::Passkey(passkey), FactorParams::Passkey(p)) => passkey.include_params(p),
      (FactorType::Stack(stack), FactorParams::Stack(p)) => stack.include_params(p),
      (FactorType::Persisted(persisted), FactorParams::Persisted(p)) => persisted.include_params(p),
      (f, _) => Err(crate::error::MFKDF2Error::InvalidDeriveParams(format!(
        "factor type mismatch: expected {} params",
        f.kind()
      ))),
    }
  }
}

impl FactorDeriveCtx<'_> {
  /// Get parameters for the factor during derivation.
  pub(crate) fn params(&self, key: Key) -> MFKDF2Result<FactorParams> {
    Ok(match self.0 {
      FactorType::Password(password) => FactorParams::Password(password.params(key)?),
      FactorType::HOTP(hotp) => FactorParams::HOTP(hotp.params(key)?),
      FactorType::Question(question) => FactorParams::Question(question.params(key)?),
      FactorType::UUID(uuid) => FactorParams::UUID(uuid.params(key)?),
      FactorType::HmacSha1(hmacsha1) => FactorParams::HmacSha1(hmacsha1.params(key)?),
      FactorType::TOTP(totp) => FactorParams::TOTP(totp.params(key)?),
      FactorType::OOBA(ooba) => FactorParams::OOBA(ooba.params(key)?),
      FactorType::Passkey(passkey) => FactorParams::Passkey(passkey.params(key)?),
      FactorType::Stack(stack) => FactorParams::Stack(stack.params(key)?),
      FactorType::Persisted(persisted) => FactorParams::Persisted(persisted.params(key)?),
    })
  }

  /// Get output for the factor during derivation.
  pub(crate) fn output(&self) -> FactorOutput {
    match self.0 {
      FactorType::Password(password) => FactorOutput::Password(password.output()),
      FactorType::HOTP(hotp) => FactorOutput::HOTP(hotp.output()),
      FactorType::Question(question) => FactorOutput::Question(question.output()),
      FactorType::UUID(uuid) => FactorOutput::UUID(uuid.output()),
      FactorType::HmacSha1(hmacsha1) => FactorOutput::HmacSha1(hmacsha1.output()),
      FactorType::TOTP(totp) => FactorOutput::TOTP(totp.output()),
      FactorType::OOBA(ooba) => FactorOutput::OOBA(ooba.output()),
      FactorType::Passkey(passkey) => FactorOutput::Passkey(passkey.output()),
      FactorType::Stack(stack) => FactorOutput::Stack(stack.output()),
      FactorType::Persisted(persisted) => FactorOutput::Persisted(persisted.output()),
    }
  }
}
