use sha2::{Digest, Sha256};

use crate::{policy::Policy, setup::key::PolicyFactor};

impl Policy {
  pub fn extract(&self) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(extract_policy_core(self));

    for factor in &self.factors {
      hasher.update(extract_factor(factor));
    }

    hasher.finalize().into()
  }
}

/// Extracts the core signable content from a policy object.
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

  hasher.finalize().into()
}

/// Extracts the signable content from a factor's params object.
pub fn extract_factor_params(factor: &PolicyFactor) -> [u8; 32] {
  let mut hasher = Sha256::new();

  hasher.update(factor.params.as_bytes());

  hasher.finalize().into()
}
