//! Policy-based key derivation combines [key stacking](`mod@crate::setup::factors::stack`) and
//! [threshold key derivation](`crate::derive::key`) behind the scenes to allow keys to be
//! setup and derived using arbitrarily-complex policies combining a number of factors.
//!
//! Policy is a JSON schema that defines the allowed combinations of factors that can be used to
//! derive the final key. It is used to validate the policy and to ensure that the key is derived
//! using the allowed factors.
mod derive;
mod evaluate;
mod logic;
mod setup;

pub use derive::derive;
pub use logic::{all, and, any, at_least, or};
pub use setup::{PolicySetupOptions, setup};

#[cfg(test)] mod tests;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{definitions::factor::FactorParams, setup::factors::stack::StackParams};

/// Policy factor contains the public parameters (encrypted secret, factor share) , construction
/// parameters (like salt, params), and other auxiliary state (kind, hint).
// TODO (autoparallel): We probably can just use the MFKDF2Factor struct directly here.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct PolicyFactor {
  /// Unique identifier for the factor
  pub id:     String,
  /// Factor type
  #[serde(rename = "type")]
  pub kind:   String,
  /// Base-64 encoded encrypted shamir share to recover the master secret
  pub pad:    String,
  /// Base-64 encoded salt value used to derive the factor secret
  pub salt:   String,
  /// Base-64 encrypted factor secret value used to reconstitute ke
  pub secret: String,
  /// Parameters required by the factor
  // TODO (@lonerapier): convert it into a factor based enum
  pub params: FactorParams,
  /// Optional [hint](`crate::definitions::mfkdf_derived_key::hints`) for the factor (in binary
  /// string format)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub hint:   Option<String>,
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for PolicyFactor {
  fn zeroize(&mut self) {
    self.salt.zeroize();
    self.secret.zeroize();
  }
}

/// MFKDF policy is a set of all allowable factor combinations that can be used to derive the final
/// key. MFKDF instance after i-th derivation consists of public construction parameters (threshold,
/// salt, etc.), per-factor public parameters (encrypted shares, secret), and factor public state
/// (params).
///
/// See [`policy::setup`](`setup::setup`), [`policy::derive`](`derive::derive`) on how to derive a
/// policy enforced key.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Policy {
  /// JSON schema URL to validate the key policy.
  #[serde(rename = "$schema")]
  pub schema:    String,
  /// Unique identifier for the policy.
  #[serde(rename = "$id")]
  pub id:        String,
  /// Threshold for the policy.
  pub threshold: u8,
  /// Base-64 encoded salt value used to derive the policy key.
  pub salt:      String,
  /// [`PolicyFactor`] combination used to derive the key in the policy.
  pub factors:   Vec<PolicyFactor>,
  /// Base-64 encoded HMAC value used to verify the policy [integrity](`crate::integrity`).
  #[serde(skip_serializing_if = "String::is_empty")]
  #[serde(default = "String::new")]
  pub hmac:      String,
  /// Additional rounds of argon2 time cost to add, beyond OWASP minimums.
  pub time:      u32,
  /// Additional argon2 memory cost to add (in KiB), beyond OWASP minimums.
  pub memory:    u32,
  /// Base-64 encoded policy key encrypted using KEK (key encapsulation key).
  /// It is used to derive other keys (params, integrity, etc.) in the policy.
  pub key:       String,
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Policy {
  fn zeroize(&mut self) {
    self.salt.zeroize();
    self.factors.zeroize();
    self.hmac.zeroize();
    self.key.zeroize();
  }
}

impl Policy {
  /// Returns a list of all factor IDs in the policy.
  pub fn ids(&self) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for factor in &self.factors {
      list.push(factor.id.clone());
      if factor.kind == "stack"
        && let FactorParams::Stack(StackParams { policy: nested }) = &factor.params
      {
        list.extend(nested.ids());
      }
    }
    list
  }

  /// Validates the policy by checking for duplicate factor IDs.
  pub fn validate(&self) -> bool {
    let list = self.ids();
    let set: HashSet<String> = list.iter().cloned().collect();
    set.len() == list.len()
  }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_ids"))]
fn policy_ids(policy: &Policy) -> Vec<String> { policy.ids() }

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_validate"))]
fn validate(policy: &Policy) -> bool { policy.validate() }
