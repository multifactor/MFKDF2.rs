//! Factor construction derive phase
//!
//! This module constructs [`MFKDF2Factor`] witnesses Wᵢⱼ for the derive phase corresponding
//! to the setup factors defined in [`crate::setup::factors`]. Each helper takes respective factor
//! secret (such as a password, OTP code, UUID, or passkey secret) plus any derive-specific options
//! and constructs a [`MFKDF2Factor`] that is used in [`crate::derive::key`] derivation.
//!
//! During the KeyDerive phase, these factors combine with the public policy state βᵢ to reconstruct
//! the underlying static source material κⱼ and ultimately recover the master secret `M` and next
//! derived key state βᵢ₊₁.
//!
//! **Note:** Factor setup/derive individually are not intended to be used in isolation, but are
//! composed through [`crate::setup::key`] (Setup) and [`crate::derive::key`] (Derive),
//! respectively, where factors supply witness material for the overall multi‑factor policy.
mod hmacsha1;
mod hotp;
mod ooba;
mod passkey;
mod password;
pub mod persisted;
mod question;
mod stack;
pub mod totp;
mod uuid;

pub use hmacsha1::hmacsha1;
pub use hotp::hotp;
pub use ooba::ooba;
pub use passkey::passkey;
pub use password::password;
pub use persisted::persisted;
pub use question::question;
pub use stack::stack;
pub use totp::totp;
pub use uuid::uuid;
