//! Derive phase [Passkey](`crate::setup::factors::passkey`) construction. It accepts the same
//! 32‑byte secret produced by a WebAuthn PRF extension or equivalent hardware‑backed primitive and
//! wraps it as an [`MFKDF2Factor`] used during the derive phase so that the passkey contributes
//! stable 256‑bit entropy across KeySetup and KeyDerive
use serde_json::Value;

use crate::{
  definitions::{FactorType, MFKDF2Factor},
  derive::FactorDerive,
  error::MFKDF2Result,
  setup::factors::passkey::Passkey,
};

impl FactorDerive for Passkey {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, _params: Self::Params) -> MFKDF2Result<()> {
    // Passkey factor has no parameters from setup
    Ok(())
  }
}

/// Factor construction derive phase for a passkey factor
///
/// Takes the same 32‑byte secret that was stored at setup time and wraps it in an
/// [`MFKDF2Factor`] suitable for [`crate::derive::key`]. The factor uses a fixed id `"passkey"`
/// during the derive phase.
///
/// # Errors
///
/// - [MFKDF2Error::InvalidSecretLength](`crate::error::MFKDF2Error::InvalidSecretLength`) from the
///   bindings helper when a non‑32‑byte slice is provided
///
/// # Example
///
/// Single‑factor setup/derive using a passkey within KeySetup/KeyDerive:
///
/// ```rust
/// # use std::collections::HashMap;
/// # use rand::{RngCore, rngs::OsRng};
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   setup::{
/// #     self,
/// #     factors::passkey::{PasskeyOptions},
/// #   },
/// #   definitions::MFKDF2Options,
/// #   derive,
/// # };
/// let mut prf = [0u8; 32];
/// OsRng.fill_bytes(&mut prf);
///
/// let setup_factor = setup::factors::passkey(prf, PasskeyOptions::default())?;
/// let setup_key = setup::key(&[setup_factor], MFKDF2Options::default())?;
///
/// let derive_factor = derive::factors::passkey(prf)?;
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("passkey".to_string(), derive_factor)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn passkey(secret: [u8; 32]) -> MFKDF2Result<MFKDF2Factor> {
  Ok(MFKDF2Factor {
    id:          Some("passkey".to_string()),
    factor_type: FactorType::Passkey(Passkey { secret: secret.to_vec() }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_passkey(secret: Vec<u8>) -> MFKDF2Result<MFKDF2Factor> {
  if secret.len() != 32 {
    return Err(crate::error::MFKDF2Error::InvalidSecretLength("passkey".to_string()));
  }

  passkey(secret.try_into().unwrap())
}
