impl crate::definitions::MFKDF2DerivedKey {
  pub fn persist_factor(&self, id: &str) -> Vec<u8> {
    let index = self.policy.factors.iter().position(|f| f.id == id).unwrap();
    self.shares[index].clone()
  }
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn derived_key_persist_factor(
  derived_key: &crate::definitions::MFKDF2DerivedKey,
  id: &str,
) -> Vec<u8> {
  derived_key.persist_factor(id)
}
