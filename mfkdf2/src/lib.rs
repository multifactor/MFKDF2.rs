#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![warn(unused_extern_crates, unreachable_pub, nonstandard_style)]
#![allow(clippy::cast_possible_truncation)]

pub mod constants;
mod crypto;
pub mod definitions;
pub mod derive;
pub mod error;
pub mod integrity;
mod log;
pub mod otpauth;
pub mod policy;
mod rng;
pub mod setup;
mod traits;

#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();
