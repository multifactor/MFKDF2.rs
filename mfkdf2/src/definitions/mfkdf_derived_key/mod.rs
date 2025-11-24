//! # MFKDF2 Derived Key
//!
//! The security properties of MFKDF allow the derived key to itself be used to authenticate end
//! users and implicitly verify all of their authentication factors. Because a properly-configured
//! MFKDF key (`K`) cannot feasibly be derived without the presentation of all constituent factors,
//! verifying a user’s derivation of `K` effectively constitutes verification of all factors.
//!
//! In practice, this means `MFKDF2DerivedKey` can safely serve as a high-entropy application root
//! key, while the embedded [`Policy`] and threshold secret-sharing scheme enable flexible recovery
//! flows (such as `t`‑of‑`n` factor policies) without weakening the guarantees provided by the
//! underlying multi-factor construction.
use std::collections::HashMap;

use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
  definitions::{bytearray::Key, entropy::MFKDF2Entropy},
  policy::Policy,
};

mod crypto;
pub mod hints;
pub mod mfdpg;
mod persistence;
pub mod reconstitution;
mod strengthening;

/// MFKDF2 Derived key after the setup or derive operation.
///
/// An [`MFKDF2DerivedKey`] bundles the static derived key material together with the resolved
/// [`Policy`] and auxiliary metadata needed for threshold recovery and factor management.
/// It is produced by the MFKDF2 setup and derive algorithms (see [`crate::setup::key`] and
/// [`crate::derive::key`]).
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct MFKDF2DerivedKey {
  /// Authentication policy describing factors, threshold, and integrity configuration associated
  /// with this key.
  pub policy:  Policy,
  /// Final 32‑byte key output of the KDF
  pub key:     Key,
  /// Internal secret material that is split into per‑factor shares for threshold recovery
  pub secret:  Vec<u8>,
  /// Shamir‑style shares of `secret`, one per factor, used by reconstitution and
  /// threshold‑management routines.
  pub shares:  Vec<Vec<u8>>,
  /// Per‑factor public outputs produced during setup or derive (such as strength metrics or
  /// factor‑specific metadata).
  pub outputs: HashMap<String, Value>,
  /// Measured and theoretical entropy estimates for the derived key, useful for auditing and
  /// security analysis.
  pub entropy: MFKDF2Entropy,
}

impl std::fmt::Display for MFKDF2DerivedKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "MFKDF2DerivedKey {{ key: {}, secret: {} }}",
      general_purpose::STANDARD.encode(self.key.as_ref()),
      general_purpose::STANDARD.encode(self.secret.clone()),
    )
  }
}
