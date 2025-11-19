//! Cryptographic functions for the MFKDF2 library.
use aes::Aes256;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, block_padding::NoPadding};
use ecb::{Decryptor, Encryptor};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

/// Derives a 32-byte key using HKDF-SHA256 with the given salt and info.
pub fn hkdf_sha256_with_info(input: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
  let hk = Hkdf::<Sha256>::new(Some(salt), input);
  let mut okm = [0u8; 32];
  hk.expand(info, &mut okm).expect("HKDF expand");
  okm
}

/// Encrypts a buffer using AES256-ECB with the given 32-byte key.
pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
  // Ensure the input is a multiple of 16 by zero-padding if necessary.
  let mut buf = {
    let mut v = data.to_vec();
    let rem = v.len() % 16;
    if rem != 0 {
      v.extend(vec![0u8; 16 - rem]);
    }
    v
  };

  let cipher = Encryptor::<Aes256>::new_from_slice(key).expect("Invalid AES-256 key");
  let padded_len = buf.len(); // now guaranteed multiple of 16
  cipher.encrypt_padded_mut::<NoPadding>(&mut buf, padded_len).expect("ECB encryption");
  buf
}

/// Decrypts a buffer using AES256-ECB with the given 32-byte key.
// TODO (@lonerapier): check every use of decrypt and unpad properly or use assert.
pub fn decrypt(mut data: Vec<u8>, key: &[u8; 32]) -> Vec<u8> {
  let cipher = Decryptor::<Aes256>::new_from_slice(key).expect("Invalid AES key");
  let _ = cipher.decrypt_padded_mut::<NoPadding>(&mut data).expect("ECB decrypt");
  data
}

/// Computes an HMAC-SHA1 over the given challenge using the provided secret.
pub fn hmacsha1(secret: &[u8], challenge: &[u8]) -> [u8; 20] {
  let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).unwrap();
  mac.update(challenge);
  mac.finalize().into_bytes().into()
}

/// Computes an HMAC-SHA256 over the given input using the provided secret.
pub fn hmacsha256(secret: &[u8], input: &[u8]) -> [u8; 32] {
  let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
  mac.update(input);
  mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
  use rand::{RngCore, rngs::OsRng};

  use super::*;

  #[test]
  fn encrypt_decrypt_roundtrip() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut data = [0u8; 32]; // multiple of 16
    OsRng.fill_bytes(&mut data);

    let encrypted = encrypt(&data, &key);
    let decrypted = decrypt(encrypted, &key);

    assert_eq!(&decrypted[..data.len()], &data[..]);
  }

  #[test]
  fn encrypt_decrypt_roundtrip_non_multiple() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut data = [0u8; 42]; // not a multiple of 16
    OsRng.fill_bytes(&mut data);

    let encrypted = encrypt(&data, &key);
    let decrypted = decrypt(encrypted, &key);

    assert_eq!(&decrypted[..data.len()], &data[..]);
  }

  #[test]
  fn decrypt_with_wrong_key() {
    let mut key1 = [0u8; 32];
    OsRng.fill_bytes(&mut key1);
    let mut key2 = [0u8; 32];
    OsRng.fill_bytes(&mut key2);

    let mut data = [0u8; 32];
    OsRng.fill_bytes(&mut data);

    let encrypted = encrypt(&data, &key1);
    let decrypted = decrypt(encrypted, &key2);

    assert_ne!(&decrypted[..data.len()], &data[..]);
  }

  #[test]
  fn decrypt_modified_ciphertext() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut data = [0u8; 32];
    OsRng.fill_bytes(&mut data);

    let mut encrypted = encrypt(&data, &key);
    encrypted[0] ^= 0xff; // Modify a byte

    let decrypted = decrypt(encrypted, &key);

    assert_ne!(&decrypted[..data.len()], &data[..]);
  }

  #[test]
  fn ciphertext_length() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    // Test with data length that is a multiple of 16
    let data1 = vec![0u8; 32];
    let encrypted1 = encrypt(&data1, &key);
    assert_eq!(encrypted1.len(), 32);

    // Test with data length that is not a multiple of 16
    let data2 = vec![0u8; 33];
    let encrypted2 = encrypt(&data2, &key);
    assert_eq!(encrypted2.len(), 48); // next multiple of 16
  }

  #[test]
  #[should_panic]
  fn decrypt_invalid_length() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let data = vec![0u8; 17]; // Not a multiple of 16
    decrypt(data, &key); // This should panic
  }

  #[test]
  fn test_hmacsha1() {
    let key = hex::decode("e60ab41d81d5494a90593d484d68f676a60a2450").unwrap();
    let challenge = "hello";

    let res = hmacsha1(&key, challenge.as_bytes());

    assert_eq!(hex::encode(res), "1292826fd25cdc59e5f83d3e11aa561610562875");
  }
}
