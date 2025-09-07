use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::Value;
// pub mod hmacsha1;
pub mod hotp;
pub mod password;
// pub mod question;
// pub mod stack;
// pub mod uuid;

// pub use hmacsha1::hmacsha1;
pub use hotp::hotp;
pub use password::password;

// pub use question::question;
// pub use stack::stack;
// pub use uuid::uuid;

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Enum)]
pub enum FactorType {
  Password(password::Password),
  HOTP(hotp::HOTP),
}

impl FactorType {
  pub fn inner(&self) -> &dyn FactorTrait {
    match self {
      FactorType::Password(password) => password,
      FactorType::HOTP(hotp) => hotp,
    }
  }

  pub fn inner_mut(&mut self) -> &mut dyn FactorTrait {
    match self {
      FactorType::Password(password) => password,
      FactorType::HOTP(hotp) => hotp,
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
  // TODO: Don't need now because we can handle the factor type in the data field (which may want
  // to be renamed) // TODO (autoparallel): This should be called "type" instead.
  // pub kind:    String,
  pub id:          Option<String>,
  pub factor_type: FactorType,
  // pub data:    Vec<u8>,
  // TODO (autoparallel): This is the factor specific salt.
  pub salt:        Vec<u8>,
  // #[serde(skip)]
  // pub params:  Option<SetupFactorFn>,
  pub entropy:     Option<u32>,
  // #[serde(skip)]
  // pub output:  Option<SetupFactorFn>,
  // #[serde(skip)]
  // pub inner: Option<Box<dyn FactorTrait>>,
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
