pub mod factors;
pub mod key;

use std::pin::Pin;

pub use key::key;

use crate::derive::factors::MFKDF2DerivedFactor;

pub type MFKDF2DerivedFactorFuture = Pin<Box<dyn Future<Output = MFKDF2DerivedFactor> + Send>>;
