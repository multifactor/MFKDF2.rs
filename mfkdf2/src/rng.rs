//! # RNG
//!
//! RNG is used to generate random bytes for the MFKDF2 algorithm. It is implemented using the
//! `rand` crate. The reason for having a separate RNG module is to allow for differential testing.
//!
//! [`GlobalRng`] is a facade around the `rand` crate's [`rand::rngs::OsRng`] to provide the same
//! interface.
//!
//! ## Differential Testing
//!
//! Differential testing is used to ensure the correctness of the library. It is enabled by the
//! `differential-test` feature flag. It is performed by comparing the output of the library with
//! the output of the reference implementation.

#[cfg(feature = "differential-test")]
mod global_rng {
  use std::cell::RefCell;

  use rand::{CryptoRng, RngCore, SeedableRng};
  use rand_chacha::ChaCha20Rng;

  /// The default seed for the global RNG.
  const DEFAULT_SEED: [u8; 32] = [10u8; 32];
  thread_local! {
    static RNG: RefCell<ChaCha20Rng> = RefCell::new(ChaCha20Rng::from_seed(DEFAULT_SEED));
  }

  pub(crate) struct GlobalRng;

  impl RngCore for GlobalRng {
    fn next_u32(&mut self) -> u32 { RNG.with(|rng| rng.borrow_mut().next_u32()) }

    fn next_u64(&mut self) -> u64 { RNG.with(|rng| rng.borrow_mut().next_u64()) }

    fn fill_bytes(&mut self, dest: &mut [u8]) { RNG.with(|rng| rng.borrow_mut().fill_bytes(dest)) }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
      RNG.with(|rng| rng.borrow_mut().try_fill_bytes(dest))
    }
  }
  impl CryptoRng for GlobalRng {}

  pub(crate) fn fill_bytes(dst: &mut [u8]) { RNG.with(|rng| rng.borrow_mut().fill_bytes(dst)); }
  pub(crate) fn next_u32() -> u32 { RNG.with(|rng| rng.borrow_mut().next_u32()) }
  pub(crate) fn gen_range_u32(max: u32) -> u32 { if max == 0 { 0 } else { next_u32() % max } }
  pub(crate) fn gen_range_u8(max: u8) -> u8 {
    if max == 0 { 0 } else { (next_u32() % max as u32) as u8 }
  }
}

#[cfg(not(feature = "differential-test"))]
mod global_rng {
  use rand::{CryptoRng, RngCore, rngs::OsRng};

  /// [`GlobalRng`] is a facade around the `rand` crate's [`rand::rngs::OsRng`] to provide the same
  /// interface.
  pub(crate) struct GlobalRng;

  impl RngCore for GlobalRng {
    fn next_u32(&mut self) -> u32 { OsRng.next_u32() }

    fn next_u64(&mut self) -> u64 { OsRng.next_u64() }

    fn fill_bytes(&mut self, dest: &mut [u8]) { OsRng.fill_bytes(dest) }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
      OsRng.try_fill_bytes(dest)
    }
  }
  impl CryptoRng for GlobalRng {}

  pub(crate) fn fill_bytes(dst: &mut [u8]) { GlobalRng.fill_bytes(dst); }

  pub(crate) fn next_u32() -> u32 { GlobalRng.next_u32() }

  pub(crate) fn gen_range_u32(max: u32) -> u32 { if max == 0 { 0 } else { next_u32() % max } }

  pub(crate) fn gen_range_u8(max: u8) -> u8 {
    if max == 0 { 0 } else { (next_u32() % u32::from(max)) as u8 }
  }
}

pub(crate) use global_rng::*;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_fill_bytes() {
    let mut buf = [0u8; 32];
    fill_bytes(&mut buf);
    println!("buf: {:?}", buf);

    let value = next_u32();
    println!("value: {:?}", value);
  }
}
