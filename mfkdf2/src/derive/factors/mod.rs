use std::pin::Pin;

use serde_json::Value;
// pub mod hotp;
pub mod password;
pub mod question;
// pub mod uuid;

pub use password::password;
pub use question::question;

pub struct MFKDF2DerivedFactor {
  pub kind:   String,
  pub data:   Vec<u8>,
  pub params: Option<Box<dyn Fn() -> Pin<Box<dyn Future<Output = Value> + Send>> + Send + Sync>>,
  pub output:
    Option<Pin<Box<dyn Fn() -> Pin<Box<dyn Future<Output = Value> + Send>> + Send + Sync>>>,
}
