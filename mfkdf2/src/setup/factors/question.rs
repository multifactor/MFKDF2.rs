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

  fn params(&self, _key: [u8; 32]) -> Value {
    json!({
      "question": self.options.question.clone().unwrap_or_default(),
    })
  }

  fn output(&self, _key: [u8; 32]) -> Value {
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
    factor_type: FactorSetupType::Question(Question {
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

  fn mock_construction() -> MFKDF2Factor {
    let options = QuestionOptions {
      id:       Some("test-question".to_string()),
      question: Some("What is your favorite color?".to_string()),
    };
    let result = question("Blue! No, Yellow!", options);
    assert!(result.is_ok());
    result.unwrap()
  }

  #[test]
  fn construction() {
    let options = QuestionOptions {
      id:       Some("test-question".to_string()),
      question: Some("What is your favorite color?".to_string()),
    };
    let result = question("Blue! No, Yellow!", options);
    assert!(result.is_ok());

    let factor = result.unwrap();
    assert_eq!(factor.id, Some("test-question".to_string()));
    assert_eq!(factor.salt.len(), 32);

    assert!(matches!(factor.factor_type, FactorType::Question(_)));
    if let FactorType::Question(q) = factor.factor_type {
      assert_eq!(q.answer, "bluenoyellow");
      assert_eq!(q.options.question, Some("What is your favorite color?".to_string()));
    }
  }

  #[test]
  fn empty_answer() {
    let options = QuestionOptions::default();
    let result = question("", options);
    assert!(matches!(result, Err(MFKDF2Error::AnswerEmpty)));
  }

  #[test]
  fn empty_id() {
    let options = QuestionOptions { id: Some("".to_string()), question: None };
    let result = question("some answer", options);
    assert!(matches!(result, Err(MFKDF2Error::MissingFactorId)));
  }

  #[test]
  fn params() {
    let factor = mock_construction();
    let question_factor: Question = match factor.factor_type {
      FactorType::Question(q) => q,
      _ => panic!("Factor type should be Question"),
    };

    let params = question_factor.params([0u8; 32]);
    assert!(params.is_object());
    assert_eq!(params["question"], "What is your favorite color?");
  }

  #[test]
  fn output() {
    let factor = mock_construction();
    let output = factor.factor_type.output([0u8; 32]);
    assert!(output.is_object());
    assert!(output["strength"].is_object());
    assert!(output["strength"]["score"].is_number());
    assert!(output["strength"]["guesses"].is_number());
    assert!(output["strength"]["guesses_log10"].is_number());
  }

  #[test]
  fn test_question_strength() {
    let factor = question("Paris", QuestionOptions {
      id:       None,
      question: Some("What is the capital of France?".to_string()),
    })
    .unwrap();
    assert_eq!(factor.entropy, Some(9));
  }

  #[test]
  fn answer_normalization() {
    let factor = question("  My answer is... 'Test 123!' ", QuestionOptions::default()).unwrap();
    if let FactorType::Question(q) = factor.factor_type {
      assert_eq!(q.answer, "myansweristest123");
    } else {
      panic!("Wrong factor type");
    }
  }
}
