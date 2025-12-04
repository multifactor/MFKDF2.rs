use crate::error::MFKDF2Result;

impl crate::definitions::MFKDF2DerivedKey {
  /// Returns an HKDF-SHA256 derived key for the given purpose and salt.
  pub fn get_subkey(&self, purpose: Option<&str>, salt: Option<&[u8]>) -> MFKDF2Result<[u8; 32]> {
    let salt = salt.unwrap_or(&[]);
    let purpose = purpose.unwrap_or("");

    // derive internal key
    let internal_key = self.derive_internal_key()?;
    // derive subkey
    Ok(crate::crypto::hkdf_sha256_with_info(&internal_key, salt, purpose.as_bytes()))
  }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_get_subkey(
  derived_key: &crate::definitions::MFKDF2DerivedKey,
  purpose: Option<String>,
  salt: Option<Vec<u8>>,
) -> MFKDF2Result<Vec<u8>> {
  let purpose = purpose.as_deref();
  let salt = salt.as_deref();
  Ok(derived_key.get_subkey(purpose, salt)?.to_vec())
}
