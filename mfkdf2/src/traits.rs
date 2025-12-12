use serde::{Deserialize, Serialize};

pub(crate) trait Factor {
  /// Public parameters for the factor
  type Params: Serialize + for<'de> Deserialize<'de>;
  /// Output for the factor
  type Output: Serialize + for<'de> Deserialize<'de>;

  fn kind(&self) -> &'static str;
  fn bytes(&self) -> Vec<u8>;
}
