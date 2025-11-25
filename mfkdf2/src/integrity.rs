//! State integrity helpers for MFKDF2.
//!
//! To prevent an untrusted server (or an attacker) from silently changing the public "state"
//! containing the policy and factor configuration, the client authenticates it with a MAC (message
//! authentication code) computed using a key derived from the user's factors.
//!
//! The functions in this module turn a [`Policy`] and each [`PolicyFactor`] into SHA-256
//! digests. These digests define exactly what bytes are covered by the MAC (for example, an
//! HMAC-SHA256 over the derived key and the extracted state).
//!
//! Any change to things like the threshold, KDF parameters, factor secrets, or salts will change
//! the MAC input and make verification fail. This defends against state-tampering attacks where an
//! attacker tries to weaken KDF parameters, modify or remove factors, or otherwise alter the public
//! state while still having it accepted as valid by an honest client.

use sha2::{Digest, Sha256};

use crate::policy::{Policy, PolicyFactor};

impl Policy {
  /// Computes the digest of an entire policy, including all factors.
  pub fn extract(&self) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(extract_policy_core(self));

    for factor in &self.factors {
      hasher.update(extract_factor(factor));
    }

    hasher.finalize().into()
  }
}

/// Hashes the core policy fields that must remain stable.
pub fn extract_policy_core(policy: &Policy) -> [u8; 32] {
  let mut hasher = Sha256::new();

  hasher.update(policy.id.as_bytes());
  hasher.update(policy.threshold.to_string().as_bytes());
  hasher.update(policy.salt.as_bytes());

  hasher.finalize().into()
}

/// Extracts the signable content from a factor object.
pub fn extract_factor(factor: &PolicyFactor) -> [u8; 32] {
  let mut hasher = Sha256::new();

  hasher.update(extract_factor_core(factor));
  hasher.update(extract_factor_params(factor));

  hasher.finalize().into()
}

/// Extracts the core signable content from a factor object.
pub fn extract_factor_core(factor: &PolicyFactor) -> [u8; 32] {
  let mut hasher = Sha256::new();

  hasher.update(factor.id.as_bytes());
  hasher.update(factor.kind.as_bytes());
  hasher.update(factor.pad.as_bytes());
  hasher.update(factor.salt.as_bytes());
  hasher.update(factor.secret.as_bytes());
  hasher.update(factor.hint.as_ref().unwrap_or(&String::new()).as_bytes());

  hasher.finalize().into()
}

/// Extracts the signable content from a factor's params object.
pub fn extract_factor_params(factor: &PolicyFactor) -> [u8; 32] {
  let mut hasher = Sha256::new();

  hasher.update(serde_json::to_string(&factor.params).unwrap().as_bytes());

  hasher.finalize().into()
}
