use thiserror::Error;
use wasm_bindgen::prelude::wasm_bindgen;

pub type MFKDF2Result<T> = Result<T, MFKDF2Error>;

#[wasm_bindgen]
#[derive(Error, Debug)]
pub enum MFKDF2Error {
  #[error("password cannot be empty")]
  PasswordEmpty,

  #[error("answer cannot be empty")]
  AnswerEmpty,

  #[error("uuid is invalid")]
  UuidInvalid,

  #[error("failed to serialize factor")]
  SerializeFactor,
}
