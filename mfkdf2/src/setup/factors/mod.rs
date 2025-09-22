use serde::{Deserialize, Serialize};
use serde_json::Value;
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
pub use passkey::passkey;
pub use password::password;
pub use question::question;
pub use stack::stack;
pub use totp::totp;
pub use uuid::uuid;

use crate::derive::FactorDerive;

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Enum)]
pub enum FactorType {
  Password(password::Password),
  HOTP(hotp::HOTP),
  Question(question::Question),
  UUID(uuid::UUID),
  HmacSha1(hmacsha1::HmacSha1),
  TOTP(totp::TOTP),
  OOBA(ooba::Ooba),
  Passkey(passkey::Passkey),
  Stack(stack::Stack),
}

impl FactorType {
  pub fn inner(&self) -> &dyn Factor {
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
    }
  }

  pub fn inner_mut(&mut self) -> &mut dyn Factor {
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
    }
  }
}

impl FactorMetadata for FactorType {
  fn kind(&self) -> String { self.inner().kind() }
}

impl FactorSetup for FactorType {
  fn bytes(&self) -> Vec<u8> { self.inner().bytes() }

  fn params(&self, key: [u8; 32]) -> Value { self.inner().params(key) }

  fn output(&self, key: [u8; 32]) -> Value { self.inner().output(key) }
}

pub trait FactorMetadata {
  fn kind(&self) -> String;
}

pub trait Factor: FactorMetadata + FactorSetup + FactorDerive {}

pub trait FactorSetup {
  fn bytes(&self) -> Vec<u8>;
  fn params(&self, key: [u8; 32]) -> Value;
  fn output(&self, key: [u8; 32]) -> Value;
}

#[derive(Clone, Serialize, Deserialize, uniffi::Record)]
pub struct MFKDF2Factor {
  pub id:          Option<String>,
  pub factor_type: FactorType,
  // TODO (autoparallel): This is the factor specific salt.
  pub salt:        Vec<u8>,
  pub entropy:     Option<u32>,
}

impl MFKDF2Factor {
  pub fn kind(&self) -> String { self.factor_type.kind() }

  pub fn data(&self) -> Vec<u8> { self.factor_type.bytes() }
}

impl std::fmt::Debug for MFKDF2Factor {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("MFKDF2Factor")
      .field("kind", &self.factor_type.kind())
      .field("id", &self.id)
      .field("data", &self.factor_type)
      .field("salt", &self.salt)
      .field("params", &"<function>")
      .field("entropy", &self.entropy)
      .field("output", &"<future>")
      .finish()
  }
}
