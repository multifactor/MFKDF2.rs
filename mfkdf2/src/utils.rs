use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, block_padding::NoPadding};
use ecb::Encryptor;
use hkdf::Hkdf;
use sha2::Sha256;
use sharks::{Share, Sharks};

pub fn hkdf_sha256(input: &[u8], salt: &[u8; 32]) -> [u8; 32] {
  let hk = Hkdf::<Sha256>::new(Some(salt), input);
  let mut okm = [0u8; 32];
  hk.expand(&[], &mut okm).expect("HKDF expand");
  okm
}

pub fn aes256_ecb_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
  // ECB works on 16-byte blocks with NO padding (JS did cipher.setAutoPadding(false)).
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

pub fn argon2id(secret: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
  // Reasonable defaults: 2 iters, 24 MiB
  let params = Params::new(24 * 1024, 2, 1, Some(32)).expect("argon2 params");
  let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
  let mut key = [0u8; 32];
  argon2.hash_password_into(secret, salt, &mut key).expect("argon2id");
  key
}

pub fn split_secret(secret: &[u8; 32], threshold: u8, shares: usize) -> Vec<Vec<u8>> {
  let sharks = Sharks(threshold);
  let dealer = sharks.dealer(secret);
  dealer.take(shares).map(|s: Share| Vec::from(&s)).collect()
}
