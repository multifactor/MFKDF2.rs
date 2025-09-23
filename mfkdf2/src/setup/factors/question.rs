use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{FactorMetadata, FactorSetup, FactorType, MFKDF2Factor},
};

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Question {
  // TODO (sambhav): does this option need to be added here?
  pub options: QuestionOptions,
  pub params:  String,
  pub answer:  String,
}

impl FactorMetadata for Question {
  fn kind(&self) -> String { "question".to_string() }
}

impl FactorSetup for Question {
  fn bytes(&self) -> Vec<u8> { self.answer.as_bytes().to_vec() }

  fn params_setup(&self, _key: [u8; 32]) -> Value {
    json!({
      "question": self.options.question.clone().unwrap_or_default(),
    })
  }

  fn output_setup(&self, _key: [u8; 32]) -> Value {
    json!({
      "strength": zxcvbn(&self.answer, &[]),
    })
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct QuestionOptions {
  pub id:       Option<String>,
  pub question: Option<String>,
}

impl Default for QuestionOptions {
  fn default() -> Self { Self { id: Some("question".to_string()), question: None } }
}

pub fn question(answer: impl Into<String>, options: QuestionOptions) -> MFKDF2Result<MFKDF2Factor> {
  let answer = answer.into();
  if answer.is_empty() {
    return Err(MFKDF2Error::AnswerEmpty);
  }

  // Validation
  if let Some(ref id) = options.id
    && id.is_empty()
  {
    return Err(crate::error::MFKDF2Error::MissingFactorId);
  }
  let id = Some(options.id.clone().unwrap_or("question".to_string()));

  let question = match options.question {
    None => String::new(),
    Some(ref ques) => ques.clone(),
  };

  let answer = answer.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "").trim().to_string();
  let strength = zxcvbn(&answer, &[]);
  let entropy = strength.guesses().ilog2();

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  let mut options = options;
  options.question = Some(question);
  options.id = id.clone();

  Ok(MFKDF2Factor {
    id,
    factor_type: FactorType::Question(Question {
      options,
      params: serde_json::to_string(&Value::Null).unwrap(),
      answer,
    }),
    salt: salt.to_vec(),
    entropy: Some(entropy),
  })
}

#[uniffi::export]
pub fn setup_question(answer: String, options: QuestionOptions) -> MFKDF2Result<MFKDF2Factor> {
  question(answer, options)
}

#[cfg(test)]
mod tests {

  use super::*;

  #[test]
  fn test_question_strength() {
    let factor = question("Paris", QuestionOptions {
      id:       None,
      question: Some("What is the capital of France?".to_string()),
    })
    .unwrap();
    assert_eq!(factor.entropy, Some(9));
  }
}
