#![doc = include_str!("../README.md")]
#![warn(missing_docs, rustdoc::missing_doc_code_examples)]
#![warn(unused_extern_crates, unreachable_pub, nonstandard_style)]

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

#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();
