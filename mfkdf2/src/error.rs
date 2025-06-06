use thiserror::Error;

pub type MFKDF2Result<T> = Result<T, MFKDF2Error>;

#[derive(Error, Debug)]
pub enum MFKDF2Error {
  #[error("password cannot be empty")]
  PasswordEmpty,

  #[error("answer cannot be empty")]
  AnswerEmpty,
}
