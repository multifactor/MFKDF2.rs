use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::setup::{
  FactorState,
  factors::{hmacsha1, hotp, ooba, passkey, password, question, stack, totp, uuid},
};

// #[cfg_attr(feature = "bindings", uniffi::export)]
pub trait FactorMetadata: std::fmt::Debug {
  fn bytes(&self) -> Vec<u8>;
  fn kind(&self) -> String;
}

// #[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Serialize, Deserialize)]
pub struct MFKDF2Factor<S: FactorState> {
  pub id:          Option<String>,
  pub factor_type: FactorType<S>,
  pub salt:        Vec<u8>,
  pub entropy:     Option<f64>,
}

use crate::setup::{Derive, Setup};
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct MFKDF2FactorSetup(MFKDF2Factor<Setup>);
pub type MFKDF2FactorDerive = MFKDF2Factor<Derive>;

impl<S: FactorState> MFKDF2Factor<S> {
  pub fn kind(&self) -> String { self.factor_type.kind() }

  pub fn data(&self) -> Vec<u8> { self.factor_type.bytes() }
}

impl<S: FactorState> std::fmt::Debug for MFKDF2Factor<S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("MFKDF2Factor")
      .field("kind", &self.kind())
      .field("id", &self.id)
      .field("data", &self.factor_type)
      .field("salt", &self.salt)
      .field("params", &"<function>")
      .field("entropy", &self.entropy)
      .field("output", &"<function>")
      .finish()
  }
}

// #[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FactorType<S: FactorState> {
  Password(password::Password),
  HOTP(hotp::HOTP),
  Question(question::Question),
  UUID(uuid::UUIDFactor),
  HmacSha1(hmacsha1::HmacSha1),
  TOTP(totp::TOTP),
  OOBA(ooba::Ooba),
  Passkey(passkey::Passkey),
  Stack(stack::Stack<S>),
  Persisted(crate::derive::factors::persisted::Persisted),
  Phantom(PhantomData<S>),
}

impl<S: FactorState> FactorMetadata for FactorType<S> {
  fn bytes(&self) -> Vec<u8> {
    match self {
      FactorType::Password(password) => password.bytes(),
      FactorType::HOTP(hotp) => hotp.bytes(),
      FactorType::Question(question) => question.bytes(),
      FactorType::UUID(uuid) => uuid.bytes(),
      FactorType::HmacSha1(hmacsha1) => hmacsha1.bytes(),
      FactorType::TOTP(totp) => totp.bytes(),
      FactorType::OOBA(ooba) => ooba.bytes(),
      FactorType::Passkey(passkey) => passkey.bytes(),
      FactorType::Stack(stack) => stack.bytes(),
      FactorType::Persisted(persisted) => persisted.bytes(),
      FactorType::Phantom(_) => unreachable!("Phantom factor should not be used in this context"),
    }
  }

  fn kind(&self) -> String {
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
      FactorType::Persisted(persisted) => persisted.kind(),
      FactorType::Phantom(_) => unreachable!("Phantom factor should not be used in this context"),
    }
  }
}
