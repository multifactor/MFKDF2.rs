use serde::{Deserialize, Serialize};

/// 32 byte key
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Key(pub [u8; 32]);

impl TryFrom<Vec<u8>> for Key {
  type Error = crate::error::MFKDF2Error;

  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
    if value.len() != 32 {
      return Err(crate::error::MFKDF2Error::InvalidKeyLength);
    }

    Ok(Key(value.try_into().unwrap()))
  }
}
impl From<Key> for Vec<u8> {
  fn from(value: Key) -> Self { value.0.to_vec() }
}
impl From<[u8; 32]> for Key {
  fn from(value: [u8; 32]) -> Self { Key(value) }
}

impl AsRef<[u8]> for Key {
  fn as_ref(&self) -> &[u8] { &self.0 }
}

impl std::ops::Deref for Key {
  type Target = [u8];

  fn deref(&self) -> &Self::Target { &self.0 }
}
