//! # RNG
//!
//! RNG is used to generate random bytes for the MFKDF2 algorithm. It is implemented using the
//! `rand` crate. The reason for having a separate RNG module is to allow for differential testing.
//!
//! [`GlobalRng`] is a facade around the `rand` crate's OsRng to provide the same interface.
//!
//! ## Differential Testing
//!
//! Differential testing is used to ensure the correctness of the library. It is enabled by the
//! `differential-test` feature flag. It is performed by comparing the output of the library with
//! the output of the reference implementation.

#[cfg(feature = "differential-test")]
mod rng {
  use std::cell::RefCell;

  use rand::{CryptoRng, RngCore, SeedableRng};
  use rand_chacha::ChaCha20Rng;

  /// The default seed for the global RNG.
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
mod rng {
  use rand::{CryptoRng, RngCore, rngs::OsRng};

  /// [`GlobalRng`] is a facade around the `rand` crate's [`rand::rngs::OsRng`] to provide the same
  /// interface.
  ///
  /// # Examples
  ///
  /// ```rust
  /// let mut rng = GlobalRng;
  /// let value = rng.next_u32();
  /// ```
  pub struct GlobalRng;

  impl RngCore for GlobalRng {
    /// Generates a random u32.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut rng = GlobalRng;
    /// let value = rng.next_u32();
    /// ```
    fn next_u32(&mut self) -> u32 { OsRng.next_u32() }

    /// Generates a random u64.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut rng = GlobalRng;
    /// let value = rng.next_u64();
    /// ```
    fn next_u64(&mut self) -> u64 { OsRng.next_u64() }

    /// Fills a byte array with random bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut rng = GlobalRng;
    /// let mut bytes = [0u8; 32];
    /// rng.fill_bytes(&mut bytes);
    /// ```
    fn fill_bytes(&mut self, dest: &mut [u8]) { OsRng.fill_bytes(dest) }

    /// Tries to fill a byte array with random bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut rng = GlobalRng;
    /// let mut bytes = [0u8; 32];
    /// rng.try_fill_bytes(&mut bytes).unwrap();
    /// ```
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
      OsRng.try_fill_bytes(dest)
    }
  }
  impl CryptoRng for GlobalRng {}

  /// Fills a byte array with random bytes.
  ///
  /// # Examples
  ///
  /// ```rust
  /// let mut rng = GlobalRng;
  /// let mut bytes = [0u8; 32];
  /// rng.fill_bytes(&mut bytes);
  /// ```
  pub fn fill_bytes(dst: &mut [u8]) { GlobalRng.fill_bytes(dst); }

  /// Generates a random u32.
  ///
  /// # Examples
  ///
  /// ```rust
  /// let mut rng = GlobalRng;
  /// let value = rng.next_u32();
  /// ```
  pub fn next_u32() -> u32 { GlobalRng.next_u32() }

  /// Generates a random u32 between 0 and the given max.
  ///
  /// # Examples
  ///
  /// ```rust
  /// let mut rng = GlobalRng;
  /// let value = rng.gen_range_u32(100);
  /// ```
  pub fn gen_range_u32(max: u32) -> u32 { if max == 0 { 0 } else { next_u32() % max } }

  /// Generates a random u8 between 0 and the given max.
  ///
  /// # Examples
  ///
  /// ```rust
  /// let mut rng = GlobalRng;
  /// let value = rng.gen_range_u8(100);
  /// ```
  pub fn gen_range_u8(max: u8) -> u8 {
    if max == 0 { 0 } else { (next_u32() % u32::from(max)) as u8 }
  }
}

pub use rng::*;

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
