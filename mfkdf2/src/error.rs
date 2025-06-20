use thiserror::Error;

pub type MFKDF2Result<T> = Result<T, MFKDF2Error>;

#[derive(Error, Debug)]
pub enum MFKDF2Error {
  #[error("password cannot be empty!")]
  PasswordEmpty,

  #[error("answer cannot be empty!")]
  AnswerEmpty,

  #[error("invalid threshold! threshold must be between 1 and the number of factors!")]
  InvalidThreshold,

  #[error("factor id is required!")]
  MissingFactorId,

  #[error("factor id must be unique!")]
  DuplicateFactorId,

  #[error(transparent)]
  DecodeError(#[from] base64::DecodeError),

  // TODO (autoparallel): This error variant should probably not even exist.
  #[error("failed to convert vector to array!")]
  TryFromVecError,

  #[error("share recovery failed!")]
  ShareRecoveryError,
}
