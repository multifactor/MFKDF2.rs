use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{
    Factor, FactorType, MFKDF2Factor,
    question::{Question, QuestionOptions},
  },
};

impl FactorDerive for Question {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.params = serde_json::to_string(&params).unwrap();
    Ok(())
  }

  fn params_derive(&self, _key: [u8; 32]) -> Value { serde_json::from_str(&self.params).unwrap() }

  fn output_derive(&self, _key: [u8; 32]) -> Value {
    json!({"strength": zxcvbn(&self.answer, &[])})
  }
}
impl Factor for Question {}

pub fn question(answer: impl Into<String>) -> MFKDF2Result<MFKDF2Factor> {
  let answer = answer.into();
  if answer.is_empty() {
    return Err(MFKDF2Error::AnswerEmpty);
  }
  let answer = answer.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "").trim().to_string();
  let strength = zxcvbn(&answer, &[]);

  Ok(MFKDF2Factor {
    id:          None,
    // TODO (@lonerapier): MaybeUninit is a better type here that is initialised at
    // [`crate::derive::FactorDeriveTrait::include_params`]
    factor_type: FactorType::Question(Question {
      options: QuestionOptions::default(),
      params:  serde_json::to_string(&Value::Null).unwrap(),
      answer:  answer.clone(),
    }),
    salt:        [0u8; 32].to_vec(),
    entropy:     Some(strength.guesses().ilog2()),
  })
}

#[uniffi::export]
pub fn derive_question(answer: String) -> MFKDF2Result<MFKDF2Factor> { question(answer) }
