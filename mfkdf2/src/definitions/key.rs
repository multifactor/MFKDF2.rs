/// 32 byte HKDF key
#[derive(Debug, Clone)]
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

// Uniffi custom type for Key
// TODO (@lonerapier): move uniffi custom type to its own crate
uniffi::custom_type!(Key, Vec<u8>);
