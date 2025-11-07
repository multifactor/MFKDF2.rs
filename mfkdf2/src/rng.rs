#[cfg(feature = "differential-test")]
mod rng_impl {
  use std::cell::RefCell;

  use rand::{CryptoRng, RngCore, SeedableRng};
  use rand_chacha::ChaCha20Rng;

  const DEFAULT_SEED: [u8; 32] = [10u8; 32];
  thread_local! {
    static RNG: RefCell<ChaCha20Rng> = RefCell::new(ChaCha20Rng::from_seed(DEFAULT_SEED));
  }

  pub struct GlobalRng;

  impl RngCore for GlobalRng {
    fn next_u32(&mut self) -> u32 { RNG.with(|rng| rng.borrow_mut().next_u32()) }

    fn next_u64(&mut self) -> u64 { RNG.with(|rng| rng.borrow_mut().next_u64()) }

    fn fill_bytes(&mut self, dest: &mut [u8]) { RNG.with(|rng| rng.borrow_mut().fill_bytes(dest)) }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
      RNG.with(|rng| rng.borrow_mut().try_fill_bytes(dest))
    }
  }
  impl CryptoRng for GlobalRng {}

  pub fn fill_bytes(dst: &mut [u8]) { RNG.with(|rng| rng.borrow_mut().fill_bytes(dst)); }
  pub fn next_u32() -> u32 { RNG.with(|rng| rng.borrow_mut().next_u32()) }
  pub fn gen_range_u32(max: u32) -> u32 { if max == 0 { 0 } else { next_u32() % max } }
  pub fn gen_range_u8(max: u8) -> u8 { if max == 0 { 0 } else { (next_u32() % max as u32) as u8 } }
}

#[cfg(not(feature = "differential-test"))]
mod rng_impl {
  use rand::{CryptoRng, RngCore, rngs::OsRng};

  pub struct GlobalRng;

  impl RngCore for GlobalRng {
    fn next_u32(&mut self) -> u32 { OsRng.next_u32() }

    fn next_u64(&mut self) -> u64 { OsRng.next_u64() }

    fn fill_bytes(&mut self, dest: &mut [u8]) { OsRng.fill_bytes(dest) }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
      OsRng.try_fill_bytes(dest)
    }
  }
  impl CryptoRng for GlobalRng {}

  pub fn fill_bytes(dst: &mut [u8]) { OsRng.fill_bytes(dst); }
  pub fn next_u32() -> u32 { OsRng.next_u32() }
  pub fn gen_range_u32(max: u32) -> u32 { if max == 0 { 0 } else { next_u32() % max } }
  pub fn gen_range_u8(max: u8) -> u8 { if max == 0 { 0 } else { (next_u32() % max as u32) as u8 } }
}

pub use rng_impl::*;

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
