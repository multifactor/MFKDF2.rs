#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct MFKDF2Entropy {
  pub real:        f64,
  pub theoretical: u32,
}
