//! Persisted‑share factor derive. Persistence allows you to save one or more of the factors used to
//! setup a multi-factor derived key (eg. as browser cookies) so that they do not need to be used to
//! derive the key in the future.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
  definitions::{FactorMetadata, FactorType, MFKDF2Factor},
  derive::FactorDerive,
  error::MFKDF2Result,
};

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Persisted {
  pub share: Vec<u8>,
}

impl FactorMetadata for Persisted {
  fn kind(&self) -> String { "persisted".to_string() }

  fn bytes(&self) -> Vec<u8> { self.share.clone() }
}

impl FactorDerive for Persisted {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, _params: Self::Params) -> MFKDF2Result<()> { Ok(()) }

  fn output(&self) -> Self::Output { Value::Null }
}

/// Factor construction derive phase for a persisted Shamir share
///
/// The `share` should be the byte slice previously obtained from a derived key via
/// `MFKDF2DerivedKey::persist_factor`. This factor constructs a [`Persisted`] factor that can be
/// passed directly to [`crate::derive::key`] without requiring any additional user interaction.
///
/// # Example
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   derive,
/// #   setup::{
/// #     self,
/// #     factors::password::{PasswordOptions, password as setup_password},
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive::factors::persisted::persisted,
/// # };
/// #
/// # fn main() -> MFKDF2Result<()> {
/// let setup_key = setup::key(
///   &[setup_password("password", PasswordOptions::default())?],
///   MFKDF2Options::default(),
/// )?;
/// let share = setup_key.persist_factor("password");
/// let factor = persisted(share)?;
///
/// let derived =
///   derive::key(&setup_key.policy, HashMap::from([("password".to_string(), factor)]), true, false)?;
/// assert_eq!(derived.key, setup_key.key);
/// # Ok(())
/// # }
/// ```
pub fn persisted(share: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> {
  Ok(MFKDF2Factor {
    id:          Some("persisted".to_string()),
    factor_type: FactorType::Persisted(Persisted { share }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_persisted(share: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> { persisted(share) }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn persisted_factor() {
    let share = vec![1, 2, 3];
    let factor = persisted(share.clone()).unwrap();
    let persisted = match factor.factor_type {
      FactorType::Persisted(persisted) => persisted,
      _ => panic!("Persisted factor should be created"),
    };
    assert_eq!(persisted.share, share);
  }
}
