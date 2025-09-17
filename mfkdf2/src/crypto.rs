use aes::Aes256;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, block_padding::NoPadding};
use ecb::{Decryptor, Encryptor};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

pub fn hkdf_sha256(input: &[u8], salt: &[u8; 32]) -> [u8; 32] {
  let hk = Hkdf::<Sha256>::new(Some(salt), input);
  let mut okm = [0u8; 32];
  hk.expand(&[], &mut okm).expect("HKDF expand");
  okm
}

pub fn hkdf_sha256_with_info(input: &[u8], salt: &[u8; 32], info: &[u8]) -> [u8; 32] {
  let hk = Hkdf::<Sha256>::new(Some(salt), input);
  let mut okm = [0u8; 32];
  hk.expand(info, &mut okm).expect("HKDF expand");
  okm
}

/// Encrypts a buffer using AES256-ECB with the given 32-byte key
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

/// Decrypts a buffer using AES256-ECB with the given 32-byte key
pub fn decrypt(mut data: Vec<u8>, key: &[u8; 32]) -> Vec<u8> {
  let cipher = Decryptor::<Aes256>::new_from_slice(key).expect("Invalid AES key");
  let _ = cipher.decrypt_padded_mut::<NoPadding>(&mut data).expect("ECB decrypt");
  data
}

pub fn hmacsha1(secret: &[u8], challenge: &[u8]) -> [u8; 20] {
  let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).unwrap();
  mac.update(challenge);
  mac.finalize().into_bytes().into()
}

pub fn hmacsha256(secret: &[u8], input: &[u8]) -> [u8; 32] {
  let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
  mac.update(input);
  mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn encrypt_decrypt() {}
}
