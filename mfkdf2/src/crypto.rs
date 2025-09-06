use aes::Aes256;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, block_padding::NoPadding};
use ecb::Encryptor;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use sha3::Sha3_256;

pub fn hkdf_sha256(input: &[u8], salt: &[u8; 32]) -> [u8; 32] {
  let hk = Hkdf::<Sha256>::new(Some(salt), input);
  let mut okm = [0u8; 32];
  hk.expand(&[], &mut okm).expect("HKDF expand");
  okm
}

pub fn aes256_ecb_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
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

pub fn aes256_ecb_decrypt(mut data: Vec<u8>, key: &[u8; 32]) -> Vec<u8> {
  use ecb::Decryptor;
  let cipher = Decryptor::<Aes256>::new_from_slice(key).expect("Invalid AES key");
  let _ = cipher.decrypt_padded_mut::<NoPadding>(&mut data).expect("ECB decrypt");
  data
}

pub fn balloon_sha3_256(input: &[u8], salt: &[u8; 32]) -> [u8; 32] {
  let mut key = [0u8; 32];
  let balloon = balloon_hash::Balloon::<Sha3_256>::default();
  balloon.hash_into(input, salt, &mut key).unwrap();
  key
}

pub fn hmacsha1(secret: &[u8], challenge: u64) -> [u8; 20] {
  let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).unwrap();
  mac.update(&challenge.to_be_bytes());
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

  // TODO: We should test this against real known test vectors.
  #[test]
  fn test_balloon_sha3_256() {
    let input = b"test";
    let salt = [0u8; 32];
    let key = balloon_sha3_256(input, &salt);
    assert_eq!(key, [
      73, 231, 77, 172, 3, 246, 133, 157, 117, 140, 46, 54, 81, 82, 218, 209, 45, 30, 196, 30, 223,
      170, 5, 13, 59, 39, 7, 52, 133, 92, 162, 246
    ]);
  }
}
