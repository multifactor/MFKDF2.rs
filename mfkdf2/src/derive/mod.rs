pub mod factors;
pub mod key;

use std::pin::Pin;

pub use key::key;
use serde_json::Value;

use crate::{derive::factors::MFKDF2DerivedFactor, error::MFKDF2Result};

pub type DeriveFactorFn = Box<
  dyn Fn(Value) -> Pin<Box<dyn Future<Output = MFKDF2Result<MFKDF2DerivedFactor>> + Send>>
    + Send
    + Sync,
>;
