use std::collections::HashSet;

use super::Policy;

#[uniffi::export]
pub fn evaluate(policy: &Policy, factor_ids: Vec<String>) -> bool {
  let factor_set: HashSet<String> = factor_ids.into_iter().collect();
  evaluate_internal(policy, &factor_set)
}

pub(crate) fn evaluate_internal(policy: &Policy, factor_set: &HashSet<String>) -> bool {
  let threshold = policy.threshold;
  let mut actual = 0;

  for factor in &policy.factors {
    if factor.kind == "stack" {
      if let Ok(nested_policy) = serde_json::from_str::<Policy>(&factor.params)
        && evaluate_internal(&nested_policy, factor_set)
      {
        actual += 1;
      }
    } else if factor_set.contains(&factor.id) {
      actual += 1;
    }
  }

  actual >= threshold
}
