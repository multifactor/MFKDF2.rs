//! # Factor Setup
//!
//! Every [`MFKDF2Factor`](`crate::definitions::MFKDF2Factor`) instance is constructed using Witness
//! Wᵢ and parameters βᵢ. Each factor performs `FactorSetup` that takes secret material σᵢ to
//! produce the initial parameters β₀ given some configuration and randomly generated static source
//! material κᵢ. The factor’s public state βᵢ then stores an encrypted version of σᵢ (using the key
//! feedback mechanism) and public helper data.
pub mod hmacsha1;
pub mod hotp;
pub mod ooba;
pub mod passkey;
pub mod password;
pub mod question;
pub mod stack;
pub mod totp;
pub mod uuid;

pub use hmacsha1::hmacsha1;
pub use hotp::hotp;
pub use ooba::ooba;
pub use passkey::passkey;
pub use password::password;
pub use question::question;
pub use stack::stack;
pub use totp::totp;
pub use uuid::uuid;

use crate::{
  definitions::{
    FactorType, Key,
    factor::{FactorMetadata, FactorParams},
  },
  error::MFKDF2Result,
  setup::FactorSetup,
};

pub(crate) struct FactorSetupCtx<'a>(pub(crate) &'a FactorType);

impl FactorType {
  /// Returns the setup implementation for the factor type.
  pub(crate) fn setup(&self) -> FactorSetupCtx<'_> { FactorSetupCtx(self) }
}

impl FactorSetupCtx<'_> {
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
      FactorType::Persisted(_) =>
        unreachable!("Persisted factor should not be used in this context"),
    })
  }

  pub(crate) fn output(&self) -> serde_json::Value {
    match self.0 {
      FactorType::Password(password) => serde_json::to_value(password.output()).unwrap(),
      FactorType::HOTP(hotp) => serde_json::to_value(hotp.output()).unwrap(),
      FactorType::Question(question) => serde_json::to_value(question.output()).unwrap(),
      FactorType::UUID(uuid) => serde_json::to_value(uuid.output()).unwrap(),
      FactorType::HmacSha1(hmacsha1) => serde_json::to_value(hmacsha1.output()).unwrap(),
      FactorType::TOTP(totp) => serde_json::to_value(totp.output()).unwrap(),
      FactorType::OOBA(ooba) => serde_json::to_value(ooba.output()).unwrap(),
      FactorType::Passkey(passkey) => serde_json::to_value(passkey.output()).unwrap(),
      FactorType::Stack(stack) => serde_json::to_value(stack.output()).unwrap(),
      FactorType::Persisted(_) =>
        unreachable!("Persisted factor should not be used in this context"),
    }
  }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn factor_type_kind(factor_type: &FactorType) -> String { factor_type.kind() }

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn factor_type_bytes(factor_type: &FactorType) -> Vec<u8> { factor_type.bytes() }

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn setup_factor_type_params(
  factor_type: &FactorType,
  key: Option<Key>,
) -> MFKDF2Result<FactorParams> {
  // TODO (@lonerapier): remove dummy key usage
  let key = key.unwrap_or_else(|| [0u8; 32].into());
  factor_type.setup().params(key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn setup_factor_type_output(factor_type: &FactorType) -> serde_json::Value {
  factor_type.setup().output()
}
