impl crate::definitions::MFKDF2DerivedKey {
  pub fn get_subkey(&self, purpose: Option<&str>, salt: Option<&[u8]>) -> [u8; 32] {
    let salt = salt.unwrap_or(&[]);
    let purpose = purpose.unwrap_or("");
    crate::crypto::hkdf_sha256_with_info(&self.key, salt, purpose.as_bytes())
  }
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_get_subkey(
  derived_key: &crate::definitions::MFKDF2DerivedKey,
  purpose: Option<String>,
  salt: Option<Vec<u8>>,
) -> Vec<u8> {
  let purpose = purpose.as_deref();
  let salt = salt.as_deref();
  derived_key.get_subkey(purpose, salt).to_vec()
}
