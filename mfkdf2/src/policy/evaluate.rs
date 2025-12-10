use std::collections::HashSet;

use super::Policy;
use crate::{policy::FactorParams, setup::factors::stack::StackParams};

impl Policy {
  /// Evaluates the policy by checking if the given factor IDs are valid and sufficient to derive
  /// the key.
  ///
  /// # Example
  ///
  /// ```rust
  /// use mfkdf2::{
  ///   policy,
  ///   policy::PolicySetupOptions,
  ///   setup::factors::password::{PasswordOptions, password},
  /// };
  /// #
  /// let setup = policy::setup(
  ///   policy::and(
  ///     policy::or(
  ///       password("password1", PasswordOptions { id: Some("pwd1".into()) })?,
  ///       password("password2", PasswordOptions { id: Some("pwd2".into()) })?,
  ///     )?,
  ///     policy::or(
  ///       password("password3", PasswordOptions { id: Some("pwd3".into()) })?,
  ///       password("password4", PasswordOptions { id: Some("pwd4".into()) })?,
  ///     )?,
  ///   )?,
  ///   PolicySetupOptions::default(),
  /// )?;
  ///
  /// // Evaluate the policy with the given factor IDs.
  /// let is_valid = setup.policy.evaluate(vec![String::from("pwd1"), String::from("pwd4")]);
  /// assert!(is_valid);
  ///
  /// // invalid policy combination
  /// let is_valid = setup.policy.evaluate(vec![String::from("pwd1"), String::from("pwd2")]);
  /// assert!(!is_valid);
  /// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
  /// ```
  pub fn evaluate(&self, factor_ids: Vec<String>) -> bool {
    let factor_set: HashSet<String> = factor_ids.into_iter().collect();
    evaluate_internal(self, &factor_set)
  }
}

/// Recursively evaluates the policy by checking policy threshold is met by the given factor IDs.
pub(super) fn evaluate_internal(policy: &Policy, factor_set: &HashSet<String>) -> bool {
  let threshold = policy.threshold;
  let mut actual = 0;

  for factor in &policy.factors {
    if factor.kind == "stack" {
      if let FactorParams::Stack(StackParams { policy: nested }) = &factor.params
        && evaluate_internal(nested, factor_set)
      {
        actual += 1;
      }
    } else if factor_set.contains(&factor.id) {
      actual += 1;
    }
  }

  actual >= threshold
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_evaluate"))]
fn policy_evaluate(policy: &Policy, factor_ids: Vec<String>) -> bool { policy.evaluate(factor_ids) }
