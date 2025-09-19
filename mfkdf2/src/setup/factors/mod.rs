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
  pub fn inner(&self) -> &dyn FactorTrait {
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

  pub fn inner_mut(&mut self) -> &mut dyn FactorTrait {
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

impl FactorTrait for FactorType {
  fn kind(&self) -> String { self.inner().kind() }

  fn bytes(&self) -> Vec<u8> { self.inner().bytes() }

  fn params_setup(&self, key: [u8; 32]) -> Value { self.inner().params_setup(key) }

  fn output_setup(&self, key: [u8; 32]) -> Value { self.inner().output_setup(key) }

  fn params_derive(&self, key: [u8; 32]) -> Value { self.inner().params_derive(key) }

  fn output_derive(&self, key: [u8; 32]) -> Value { self.inner().output_derive(key) }

  fn include_params(&mut self, params: Value) { self.inner_mut().include_params(params) }
}

pub trait FactorTrait {
  fn kind(&self) -> String;
  fn bytes(&self) -> Vec<u8>;
  fn params_setup(&self, key: [u8; 32]) -> Value;
  fn output_setup(&self, key: [u8; 32]) -> Value;
  fn include_params(&mut self, params: Value);
  fn params_derive(&self, key: [u8; 32]) -> Value;
  fn output_derive(&self, key: [u8; 32]) -> Value;
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
