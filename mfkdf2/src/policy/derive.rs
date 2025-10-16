use std::collections::{HashMap, HashSet};

use crate::{
  definitions::{MFKDF2DerivedKey, MFKDF2Factor},
  derive::factors::stack::stack as create_stack_factor,
  error::{MFKDF2Error, MFKDF2Result},
  policy::{Policy, evaluate::evaluate_internal},
  setup::Derive,
};

fn expand(
  policy: &Policy,
  factors: &HashMap<String, MFKDF2Factor<Derive>>,
  factor_set: &HashSet<String>,
) -> MFKDF2Result<HashMap<String, MFKDF2Factor<Derive>>> {
  let mut parsed_factors = HashMap::new();

  for factor in &policy.factors {
    if factor.kind == "stack" {
      if let Ok(nested_policy) = serde_json::from_str::<Policy>(&factor.params)
        && evaluate_internal(&nested_policy, factor_set)
      {
        let nested_expanded = expand(&nested_policy, factors, factor_set)?;
        let stack_factor = create_stack_factor(nested_expanded)?;
        parsed_factors.insert(factor.id.clone(), stack_factor);
      }
    } else if factor_set.contains(&factor.id)
      && let Some(factor_impl) = factors.get(&factor.id)
    {
      parsed_factors.insert(factor.id.clone(), factor_impl.clone());
    }
  }

  Ok(parsed_factors)
}

pub fn derive(
  policy: Policy,
  factors: HashMap<String, MFKDF2Factor<Derive>>,
  verify: Option<bool>,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  if !policy.validate() {
    return Err(MFKDF2Error::DuplicateFactorId);
  }

  let factor_set: HashSet<String> = factors.keys().cloned().collect();
  if !evaluate_internal(&policy, &factor_set) {
    return Err(MFKDF2Error::InvalidThreshold);
  }

  let expanded_factors = expand(&policy, &factors, &factor_set)?;

  crate::derive::key::key(policy, expanded_factors, verify.unwrap_or(true), false)
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn policy_derive(
  policy: Policy,
  factors: HashMap<String, MFKDF2Factor<Derive>>,
  verify: Option<bool>,
) -> MFKDF2Result<MFKDF2DerivedKey> {
  derive(policy, factors, verify)
}
