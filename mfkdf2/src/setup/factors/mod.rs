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
pub enum FactorSetupType {
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

impl FactorSetupType {
  pub fn inner(&self) -> &dyn FactorSetupTrait {
    match self {
      FactorSetupType::Password(password) => password,
      FactorSetupType::HOTP(hotp) => hotp,
      FactorSetupType::Question(question) => question,
      FactorSetupType::UUID(uuid) => uuid,
      FactorSetupType::HmacSha1(hmacsha1) => hmacsha1,
      FactorSetupType::TOTP(totp) => totp,
      FactorSetupType::OOBA(ooba) => ooba,
      FactorSetupType::Passkey(passkey) => passkey,
      FactorSetupType::Stack(stack) => stack,
    }
  }

  pub fn inner_mut(&mut self) -> &mut dyn FactorSetupTrait {
    match self {
      FactorSetupType::Password(password) => password,
      FactorSetupType::HOTP(hotp) => hotp,
      FactorSetupType::Question(question) => question,
      FactorSetupType::UUID(uuid) => uuid,
      FactorSetupType::HmacSha1(hmacsha1) => hmacsha1,
      FactorSetupType::TOTP(totp) => totp,
      FactorSetupType::OOBA(ooba) => ooba,
      FactorSetupType::Passkey(passkey) => passkey,
      FactorSetupType::Stack(stack) => stack,
    }
  }
}

impl FactorSetupTrait for FactorSetupType {
  fn kind(&self) -> String { self.inner().kind() }

  fn bytes(&self) -> Vec<u8> { self.inner().bytes() }

  fn params_setup(&self, key: [u8; 32]) -> Value { self.inner().params_setup(key) }

  fn output_setup(&self, key: [u8; 32]) -> Value { self.inner().output_setup(key) }
}

pub trait FactorSetupTrait {
  fn kind(&self) -> String;
  fn bytes(&self) -> Vec<u8>;
  fn params_setup(&self, key: [u8; 32]) -> Value;
  fn output_setup(&self, key: [u8; 32]) -> Value;
}

#[derive(Clone, Serialize, Deserialize, uniffi::Record)]
pub struct MFKDF2Factor {
  pub id:          Option<String>,
  pub factor_type: FactorSetupType,
  // TODO (autoparallel): This is the factor specific salt.
  pub salt:        Vec<u8>,
  pub entropy:     Option<u32>,
}

impl MFKDF2Factor {
  pub fn kind(&self) -> String { self.factor_type.kind() }
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
