/// Entropy estimates for a single MFKDF2 factor.
///
/// This type tracks how hard a factor is to guess, measured in bits of entropy.
///
/// In general, `real` should be less than or equal to `theoretical`. Together they give a
/// practical and a theoretical view of factor's strength.
///
/// We recommend using "real" for most practical purposes. Entropy is only provided on key setup and
/// is not available on subsequent derivations.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct MFKDF2Entropy {
  /// Conservative estimate based on how the factor is actually produced or used. Calculated
  /// using Dropbox's `zxcvbn` estimator.
  pub real:        f64,
  /// Upper-bound estimate of the factor's strength.
  pub theoretical: u32,
}
