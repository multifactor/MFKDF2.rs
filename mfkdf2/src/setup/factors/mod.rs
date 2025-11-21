//! # Factor Setup
//!
//! Every [Factor](`crate::definitions::MFKDF2Factor`) instance is constructed using Witness
//! Wᵢ and parameters βᵢ. Each factor uses [FactorSetup](`crate::setup::FactorSetup`) that takes
//! secret material σᵢ to produce the initial parameters β₀ given some configuration and randomly
//! generated static source material κᵢ. The factor’s public state βᵢ then stores an encrypted
//! version of σᵢ (using the key feedback mechanism) and public helper data.
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
use serde_json::Value;
pub use stack::stack;
pub use totp::totp;
pub use uuid::uuid;

use crate::{
  definitions::{FactorMetadata, FactorType, Key},
  error::MFKDF2Result,
  setup::FactorSetup,
};

impl FactorType {
  /// Returns the setup implementation for the factor type.
  pub fn setup(&self) -> &dyn FactorSetup<Params = Value, Output = Value> {
    match self {
      FactorType::Password(password) => password,
      FactorType::HOTP(hotp) => hotp,
      FactorType::Question(question) => question,
      FactorType::UUID(uuid) => uuid,
      FactorType::HmacSha1(hmacsha1) => hmacsha1,
      FactorType::TOTP(totp) => totp,
      FactorType::OOBA(ooba) => ooba,
      FactorType::Passkey(passkey) => passkey,
      FactorType::Stack(stack) => stack,
      FactorType::Persisted(_) =>
        unreachable!("Persisted factor should not be used in this context"),
    }
  }
}

impl FactorSetup for FactorType {
  type Output = Value;
  type Params = Value;

  fn params(&self, key: Key) -> MFKDF2Result<Self::Params> { self.setup().params(key) }

  fn output(&self) -> Self::Output { self.setup().output() }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn factor_type_kind(factor_type: &FactorType) -> String { factor_type.kind() }

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn factor_type_bytes(factor_type: &FactorType) -> Vec<u8> { factor_type.bytes() }

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn setup_factor_type_params(factor_type: &FactorType, key: Option<Key>) -> MFKDF2Result<Value> {
  // TODO (@lonerapier): remove dummy key usage
  let key = key.unwrap_or_else(|| [0u8; 32].into());
  factor_type.params(key)
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn setup_factor_type_output(factor_type: &FactorType) -> Value { factor_type.output() }
