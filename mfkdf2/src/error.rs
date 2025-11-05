pub type MFKDF2Result<T> = Result<T, MFKDF2Error>;

// TODO (autoparallel): It may be worth making this have inner errors, e.g., for factors and other
// things. That is usually not my style, but it may be nicer for the caller as long as destructuring
// the error is not too painful.
#[cfg_attr(feature = "bindings", derive(uniffi::Error), uniffi(flat_error))]
#[derive(thiserror::Error, Debug)]
pub enum MFKDF2Error {
  #[error("password cannot be empty!")]
  PasswordEmpty,

  #[error("answer cannot be empty!")]
  AnswerEmpty,

  #[error("invalid threshold! threshold must be between 1 and the number of factors!")]
  InvalidThreshold,

  #[error("factor {0} does not exist!")]
  MissingFactor(String),

  #[error("factor id is required!")]
  MissingFactorId,

  #[error("factor id must be unique!")]
  DuplicateFactorId,

  #[error(transparent)]
  DecodeError(#[from] base64::DecodeError),

  #[error(transparent)]
  RsaError(#[from] rsa::errors::Error),

  // TODO (autoparallel): This error variant should probably not even exist.
  #[error("failed to convert vector to array!")]
  TryFromVecError,

  #[error("share recovery failed!")]
  ShareRecoveryError,

  #[error("invalid key length")]
  InvalidKeyLength,

  #[error("invalid secret length for factor {0}")]
  InvalidSecretLength(String),

  #[error("policy integrity check failed")]
  PolicyIntegrityCheckFailed,

  #[error("invalid hmac key!")]
  InvalidHmacKey,

  #[error("invalid HOTP digits! digits must be between 6 and 8")]
  InvalidHOTPDigits,

  #[error("invalid TOTP digits! digits must be between 6 and 8")]
  InvalidTOTPDigits,

  #[error("TOTP window exceeded")]
  TOTPWindowExceeded,

  #[error("invalid secret")]
  InvalidSecret,

  #[error("missing otpauth url options: {0}")]
  MissingOtpAuthUrlOptions(&'static str),

  #[error("invalid uuid")]
  InvalidUuid,

  #[error("invalid ooba length! length must be between 1 and 32")]
  InvalidOobaLength,

  #[error("missing ooba key")]
  MissingOobaKey,

  #[error("invalid ooba key")]
  InvalidOobaKey,

  #[error("invalid ooba code")]
  InvalidOobaCode,

  #[error("missing setup params: {0}")]
  MissingSetupParams(String),

  #[error("missing output params: {0}")]
  InvalidSetupParams(String),

  #[error("missing derive params: {0}")]
  MissingDeriveParams(String),

  #[error("invalid derive params: {0}")]
  InvalidDeriveParams(String),

  #[error("hint does not match for factor {0}")]
  HintMismatch(String),

  #[error("invalid hint length: {0}")]
  InvalidHintLength(&'static str),

  #[error(transparent)]
  Argon2Error(#[from] argon2::Error),

  #[error(transparent)]
  SerializeError(#[from] serde_json::Error),
}
