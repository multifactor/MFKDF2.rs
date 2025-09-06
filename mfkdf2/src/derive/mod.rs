pub mod factors;
pub mod key;

use std::{pin::Pin, rc::Rc};

pub use key::key;
use serde_json::Value;

use crate::{derive::factors::MFKDF2DerivedFactor, error::MFKDF2Result};

pub type DeriveFactorFn =
  Rc<dyn Fn(Value) -> Pin<Box<dyn Future<Output = MFKDF2Result<MFKDF2DerivedFactor>>>>>;
