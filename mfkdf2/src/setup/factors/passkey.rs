//! Passkey factor setup.
//!
//! This factor is intended for **hardware‑backed credentials** such as WebAuthn
//! passkeys bound to a platform authenticator. Instead of consuming a traditional
//! WebAuthn signature (which is intentionally non‑deterministic to prevent replay
//! attacks), the factor expects a stable 32‑byte secret produced by the WebAuthn
//! PRF extension or an equivalent key‑derivation mechanism.
//!
//! Conceptually:
//! - a passkey authenticator holds a signing key on a curve such as secp256r1 and exposes a PRF
//!   interface `prf(challenge) → prf_key`
//! - during registration, the relying party requests a PRF evaluation on a fixed challenge value,
//!   yielding a deterministic 32‑byte `prf_key`
//! - that `prf_key` is stored by the application as passkey factor material and wrapped here as
//!   high‑entropy input to MFKDF2
//!
//! Because the same PRF evaluation is used in both setup and derive, the factor
//! behaves like a constant‑entropy hardware token: as long as the user unlocks
//! the passkey and the authenticator returns the same 32‑byte value, the MFKDF2
//! key derivation receives identical factor bytes.

use serde::{Deserialize, Serialize};

use crate::{
  definitions::{FactorMetadata, FactorType, MFKDF2Factor},
  error::MFKDF2Result,
  setup::FactorSetup,
};

/// Passkey factor state
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Passkey {
  /// 32‑byte secret derived from the passkey’s WebAuthn PRF output or equivalent
  /// hardware‑protected key
  pub secret: Vec<u8>,
}

impl FactorMetadata for Passkey {
  fn kind(&self) -> String { "passkey".to_string() }

  fn bytes(&self) -> Vec<u8> { self.secret.clone() }
}

impl FactorSetup for Passkey {
  type Output = serde_json::Value;
  type Params = serde_json::Value;
}

/// Options for configuring a passkey factor
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyOptions {
  /// Optional application-defined identifier for the factor. Defaults to `"passkey"`. If
  /// provided, it must be non-empty.
  pub id: Option<String>,
}

impl Default for PasskeyOptions {
  fn default() -> Self { Self { id: Some("passkey".to_string()) } }
}

/// Creates a passkey factor from a 32‑byte secret
///
/// This constructor is intended for flows where a client or middleware layer has
/// already obtained a deterministic 32‑byte value from a WebAuthn PRF operation
/// or similar hardware‑backed primitive. The function does not perform any WebAuthn
/// protocol steps; it only validates the logical factor identifier and wraps the
/// provided secret as MFKDF2 factor material with a fixed 256‑bit entropy estimate.
///
/// # Errors
/// - [MFKDF2Error::MissingFactorId](`crate::error::MFKDF2Error::MissingFactorId`) if `options.id`
///   is present but empty
///
/// # Example
///
/// ```rust
/// use mfkdf2::setup::factors::passkey::{PasskeyOptions, passkey};
/// use rand::{RngCore, rngs::OsRng};
/// #
/// // application stores a per‑credential PRF output from the platform authenticator
/// let mut prf = [0u8; 32];
/// OsRng.fill_bytes(&mut prf);
///
/// let factor = passkey(prf, PasskeyOptions::default())?;
/// assert_eq!(factor.id.as_deref(), Some("passkey"));
/// assert_eq!(factor.data().len(), 32);
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
pub fn passkey(secret: [u8; 32], options: PasskeyOptions) -> MFKDF2Result<MFKDF2Factor> {
  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let id = options.id.unwrap_or("passkey".to_string());

  Ok(MFKDF2Factor {
    id:          Some(id),
    factor_type: FactorType::Passkey(Passkey { secret: secret.to_vec() }),
    entropy:     Some(256.0),
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn setup_passkey(secret: Vec<u8>, options: PasskeyOptions) -> MFKDF2Result<MFKDF2Factor> {
  if secret.len() != 32 {
    return Err(crate::error::MFKDF2Error::InvalidSecretLength("passkey".to_string()));
  }

  passkey(secret.try_into().unwrap(), options)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn passkey_errors() {
    let factor = passkey([0u8; 32], PasskeyOptions { id: Some("".to_string()) });
    assert!(matches!(factor, Err(crate::error::MFKDF2Error::MissingFactorId)));
  }
}
