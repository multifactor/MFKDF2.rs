pub mod derive;
pub mod evaluate;
pub mod logic;
pub mod setup;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json as json;

use crate::setup::key::PolicyFactor;

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq, uniffi::Record)]
pub struct Policy {
  #[serde(rename = "$schema")]
  pub schema:    String,
  #[serde(rename = "$id")]
  pub id:        String,
  pub threshold: u8,
  pub salt:      String,
  pub factors:   Vec<PolicyFactor>,
  pub hmac:      String,
  pub time:      u32,
  pub memory:    u32,
  pub key:       String,
}

impl Policy {
  // validate
  pub fn ids(&self) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for factor in &self.factors {
      list.push(factor.id.clone());
      if factor.kind == "stack" {
        if let Ok(nested) = json::from_str::<Policy>(&factor.params) {
          list.extend(nested.ids());
        }
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
