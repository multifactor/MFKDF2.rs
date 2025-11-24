use serde::{Deserialize, Serialize};

/// Generic fixed-size byte array used as the basis for key-like types.
#[derive(Debug, Clone, PartialEq)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

/// 32 byte key
pub type Key = ByteArray<32>;

/// 32 byte salt
pub type Salt = ByteArray<32>;

impl<const N: usize> TryFrom<Vec<u8>> for ByteArray<N> {
  type Error = crate::error::MFKDF2Error;

  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
    if value.len() != N {
      return Err(crate::error::MFKDF2Error::InvalidKeyLength);
    }

    Ok(ByteArray(value.try_into().unwrap()))
  }
}

impl<const N: usize> From<ByteArray<N>> for Vec<u8> {
  fn from(value: ByteArray<N>) -> Self { value.0.to_vec() }
}

impl<const N: usize> From<[u8; N]> for ByteArray<N> {
  fn from(value: [u8; N]) -> Self { ByteArray(value) }
}

impl<const N: usize> AsRef<[u8]> for ByteArray<N> {
  fn as_ref(&self) -> &[u8] { &self.0 }
}

impl<const N: usize> std::ops::Deref for ByteArray<N> {
  type Target = [u8];

  fn deref(&self) -> &Self::Target { &self.0 }
}

// Implement traits specifically for 32‑byte keys to satisfy serde and default bounds.

impl Default for ByteArray<32> {
  fn default() -> Self { ByteArray([0u8; 32]) }
}

impl Serialize for ByteArray<32> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where S: serde::Serializer {
    serializer.serialize_newtype_struct("Key", &self.0)
  }
}

impl<'de> Deserialize<'de> for ByteArray<32> {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where D: serde::Deserializer<'de> {
    struct KeyVisitor;

    impl<'de> serde::de::Visitor<'de> for KeyVisitor {
      type Value = ByteArray<32>;

      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a 32-byte array for Key")
      }

      fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
      where D: serde::Deserializer<'de> {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(ByteArray(bytes))
      }
    }

    deserializer.deserialize_newtype_struct("Key", KeyVisitor)
  }
}
