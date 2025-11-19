pub mod derive;
pub mod evaluate;
pub mod logic;
pub mod setup;

#[cfg(test)] mod tests;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// TODO (autoparallel): We probably can just use the MFKDF2Factor struct directly here.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct PolicyFactor {
  pub id:     String,
  #[serde(rename = "type")]
  pub kind:   String,
  pub pad:    String,
  pub salt:   String,
  pub secret: String,
  // TODO (@lonerapier): convert it into a factor based enum
  pub params: Value,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub hint:   Option<String>,
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct Policy {
  #[serde(rename = "$schema")]
  pub schema:    String,
  #[serde(rename = "$id")]
  pub id:        String,
  pub threshold: u8,
  pub salt:      String,
  pub factors:   Vec<PolicyFactor>,
  #[serde(skip_serializing_if = "String::is_empty")]
  #[serde(default = "String::new")]
  pub hmac:      String,
  pub time:      u32,
  pub memory:    u32,
  pub key:       String,
}

impl Policy {
  pub fn ids(&self) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for factor in &self.factors {
      list.push(factor.id.clone());
      if factor.kind == "stack"
        && let Ok(nested) = serde_json::from_value::<Policy>(factor.params.clone())
      {
        list.extend(nested.ids());
      }
    }
    list
  }

  pub fn validate(&self) -> bool {
    let list = self.ids();
    let set: HashSet<String> = list.iter().cloned().collect();
    set.len() == list.len()
  }
}

#[cfg_attr(feature = "bindings", uniffi::export(name = "policy_validate"))]
pub fn validate(policy: &Policy) -> bool { policy.validate() }
