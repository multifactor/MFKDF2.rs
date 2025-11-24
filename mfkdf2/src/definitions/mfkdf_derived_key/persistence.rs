impl crate::definitions::MFKDF2DerivedKey {
  /// Persistence allows you to save one or more of the factors used to setup a multi-factor derived
  /// key (eg. as browser cookies) so that they do not need to be used to derive the key in the
  /// future.
  ///
  /// # Example
  ///
  /// ```rust
  /// use mfkdf2::{
  ///   definitions::MFKDF2Options,
  ///   error::MFKDF2Error,
  ///   setup::{
  ///     self,
  ///     factors::{password, password::PasswordOptions},
  ///   },
  /// };
  /// let setup_key =
  ///   setup::key(&[password("password", PasswordOptions::default())?], MFKDF2Options::default())?;
  /// let share = setup_key.persist_factor("password");
  /// #   Ok::<(), mfkdf2::error::MFKDF2Error>(())
  /// ```
  pub fn persist_factor(&self, id: &str) -> Vec<u8> {
    let index = self.policy.factors.iter().position(|f| f.id == id).unwrap();
    self.shares[index].clone()
  }
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
fn derived_key_persist_factor(
  derived_key: &crate::definitions::MFKDF2DerivedKey,
  id: &str,
) -> Vec<u8> {
  derived_key.persist_factor(id)
}
