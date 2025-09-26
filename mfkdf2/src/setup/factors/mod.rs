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

  pub fn setup(&self) -> &dyn FactorSetup {
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

  pub fn setup_mut(&mut self) -> &mut dyn FactorSetup {
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
  fn kind(&self) -> String { self.kind() }
}

impl FactorSetup for FactorType {
  fn bytes(&self) -> Vec<u8> { self.setup().bytes() }

  fn setup(&self, key: [u8; 32]) -> Value { self.setup().setup(key) }

  fn output(&self, key: [u8; 32]) -> Value { self.setup().output(key) }
}

pub trait FactorMetadata {
  fn kind(&self) -> String;
}

// TODO (@lonerapier): refactor trait system with more associated types
// TODO: add default + debug as well
pub trait FactorSetup {
  fn bytes(&self) -> Vec<u8>;
  fn setup(&self, key: [u8; 32]) -> Value;
  fn output(&self, key: [u8; 32]) -> Value;
}

// TODO (@lonerapier): move factor to its own module
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
