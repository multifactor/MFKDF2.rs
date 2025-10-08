use serde::{Deserialize, Serialize};

use crate::setup::{
  FactorSetup,
  factors::{hmacsha1, hotp, ooba, passkey, password, question, stack, totp, uuid},
};

#[cfg_attr(feature = "bindings", uniffi::export)]
pub trait FactorMetadata: Send + Sync + std::fmt::Debug {
  fn kind(&self) -> String;
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Serialize, Deserialize)]
pub struct MFKDF2Factor {
  pub id:          Option<String>,
  pub factor_type: FactorType,
  pub salt:        Vec<u8>,
  pub entropy:     Option<f64>,
}

impl MFKDF2Factor {
  pub fn kind(&self) -> String { self.factor_type.kind() }

  pub fn data(&self) -> Vec<u8> { self.factor_type.bytes() }
}

impl std::fmt::Debug for MFKDF2Factor {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("MFKDF2Factor")
      .field("kind", &self.kind())
      .field("id", &self.id)
      .field("data", &self.factor_type)
      .field("salt", &self.salt)
      .field("params", &"<function>")
      .field("entropy", &self.entropy)
      .field("output", &"<future>")
      .finish()
  }
}

#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FactorType {
  Password(password::Password),
  HOTP(hotp::HOTP),
  Question(question::Question),
  UUID(uuid::UUIDFactor),
  HmacSha1(hmacsha1::HmacSha1),
  TOTP(totp::TOTP),
  OOBA(ooba::Ooba),
  Passkey(passkey::Passkey),
  Stack(stack::Stack),
}

impl FactorType {
  pub fn kind(&self) -> String {
    match self {
      FactorType::Password(password) => password.kind(),
      FactorType::HOTP(hotp) => hotp.kind(),
      FactorType::Question(question) => question.kind(),
      FactorType::UUID(uuid) => uuid.kind(),
      FactorType::HmacSha1(hmacsha1) => hmacsha1.kind(),
      FactorType::TOTP(totp) => totp.kind(),
      FactorType::OOBA(ooba) => ooba.kind(),
      FactorType::Passkey(passkey) => passkey.kind(),
      FactorType::Stack(stack) => stack.kind(),
    }
  }
}
