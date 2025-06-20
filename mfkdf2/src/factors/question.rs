use serde::{Deserialize, Serialize};
use serde_json::json;
use zxcvbn::{Entropy, Score, zxcvbn};

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::Material,
};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Question {
  question: String,
  answer:   String,
  score:    Score,
  entropy:  u32,
}

impl Question {
  pub fn new(question: impl Into<String>, answer: impl Into<String>) -> MFKDF2Result<Self> {
    let question = question.into();
    let answer = answer.into();
    if answer.is_empty() {
      return Err(MFKDF2Error::AnswerEmpty);
    }
    let answer =
      answer.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "").trim().to_string();
    let strength = zxcvbn(&answer, &[]);
    Ok(Self { question, answer, score: strength.score(), entropy: strength.guesses().ilog2() })
  }
}

impl From<Question> for Material {
  fn from(question: Question) -> Self {
    Self {
      id:      None,
      kind:    "question".to_string(),
      data:    question.answer.as_bytes().to_vec(),
      output:  json!({ "score": question.score }),
      entropy: question.entropy,
    }
  }
}

#[cfg(test)]
mod tests {
  use zxcvbn::Score;

  use super::*;

  #[test]
  fn test_question_new() {
    let question = Question::new("What is the capital of France?", "Paris").unwrap();
    assert_eq!(question.question, "What is the capital of France?");
    assert_eq!(question.answer, "paris");
    assert_eq!(question.score, Score::Zero);

    let question = Question::new("What is the capital of France?", "ParIS    ()*@&$#").unwrap();
    assert_eq!(question.question, "What is the capital of France?");
    assert_eq!(question.answer, "paris");
    assert_eq!(question.score, Score::Zero);
  }

  #[test]
  fn test_question_strength() {
    let question = Question::new("What is the capital of France?", "Paris");
    let factor: Material = question.unwrap().into();
    assert_eq!(factor.output, json!({ "score": Score::Zero }));
    assert_eq!(factor.entropy, 9);
  }
}
