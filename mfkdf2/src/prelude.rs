//! # MFKDF2 Prelude
//!
//! This module provides a comprehensive prelude that re-exports the most commonly used types,
//! traits, and functions from the MFKDF2 crate. This is designed to make testing, examples,
//! and development more ergonomic by reducing import boilerplate.
pub use crate::{
  constants::SECRET_SHARING_POLY,
  definitions::{FactorType, MFKDF2DerivedKey, MFKDF2Factor, MFKDF2Options, factor::FactorParams},
  derive::{
    self,
    factors::{
      hmacsha1 as derive_hmacsha1, hotp as derive_hotp, ooba as derive_ooba,
      passkey as derive_passkey, password as derive_password, persisted as derive_persisted,
      question as derive_question, stack as derive_stack, totp as derive_totp,
      totp::TOTPDeriveOptions, uuid as derive_uuid,
    },
  },
  error::{MFKDF2Error, MFKDF2Result},
  otpauth::{HashAlgorithm, Kind, OtpAuthUrlOptions, generate_otp_token},
  policy::{self, Policy, PolicySetupOptions},
  setup::{
    self,
    factors::{
      hmacsha1::{HmacSha1Options, HmacSha1Output, hmacsha1 as setup_hmacsha1},
      hotp::{HOTPOptions, HOTPOutput, hotp as setup_hotp},
      ooba::{OobaOptions, OobaOutput, ooba as setup_ooba},
      passkey::{PasskeyOptions, PasskeyOutput, passkey as setup_passkey},
      password::{PasswordOptions, PasswordOutput, password as setup_password},
      question::{QuestionOptions, QuestionOutput, question as setup_question},
      stack::{StackOptions, StackOutput, stack as setup_stack},
      totp::{TOTPOptions, TOTPOutput, totp as setup_totp},
      uuid::{UUIDFactorOutput, UUIDOptions, uuid as setup_uuid},
    },
  },
};
