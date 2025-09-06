uniffi::setup_scaffolding!();

use std::{future::Future, pin::Pin};

use serde_json::Value;

use crate::error::MFKDF2Result;

pub mod crypto;
pub mod derive;
pub mod error;
pub mod setup;

pub type FactorMaterialFn =
  Box<dyn Fn(Value) -> Pin<Box<dyn Future<Output = MFKDF2Result<Value>>>>>;
