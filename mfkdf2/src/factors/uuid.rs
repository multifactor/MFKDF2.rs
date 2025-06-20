use serde_json::Value;
pub use uuid::Uuid;

use crate::factors::Material;

impl Into<Material> for Uuid {
  fn into(self) -> Material {
    Material {
      id:      None,
      kind:    "uuid".to_string(),
      data:    self.to_string().as_bytes().to_vec(),
      output:  Value::String(self.to_string()),
      // TODO (autoparallel): Calculate entropy
      entropy: 0,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_uuid_factor() {
    let uuid = Uuid::from_u128(123_456_789_012);
    let factor: Material = uuid.into();
    assert_eq!(factor.id, None);
    assert_eq!(factor.kind, "uuid");
    assert_eq!(factor.data, uuid.to_string().as_bytes().to_vec());
    assert_eq!(factor.output, Value::String(uuid.to_string()));
    assert_eq!(factor.entropy, 0);
  }
}
