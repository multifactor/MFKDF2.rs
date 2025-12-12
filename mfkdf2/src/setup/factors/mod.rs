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
  definitions::{FactorType, Key, factor::FactorParams},
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
    }; unreachable_persisted)
  }

  pub(crate) fn output(&self) -> serde_json::Value {
    factor_dispatch_output!(self.0, output() => {
      Password, HOTP, Question, UUID, HmacSha1, TOTP, OOBA, Passkey, Stack
    }; unreachable_persisted)
  }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn factor_type_kind(factor_type: &FactorType) -> String { factor_type.kind().to_string() }

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
