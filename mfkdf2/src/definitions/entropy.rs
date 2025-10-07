#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct MFKDF2Entropy {
  pub real:        u32,
  pub theoretical: u32,
}
