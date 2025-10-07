#[derive(
  Clone, Debug, Default, serde::Serialize, serde::Deserialize, Eq, PartialEq, uniffi::Record,
)]
pub struct MFKDF2Entropy {
  pub real:        u32,
  pub theoretical: u32,
}
