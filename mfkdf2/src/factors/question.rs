use zxcvbn::{Entropy, zxcvbn};

use super::FactorMaterial;
use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::GenericFactor,
};

pub struct Question {
  question: String,
  answer:   String,
}

impl Question {
  pub fn new(question: impl Into<String>, answer: impl Into<String>) -> Self {
    Self { question: question.into(), answer: answer.into() }
  }
}

impl FactorMaterial for Question {
  type Output = Entropy;
  type Params = ();

  fn material(self) -> MFKDF2Result<GenericFactor<Self>> {
    let answer = self.answer;
    let question = self.question;
    if answer.is_empty() {
      return Err(MFKDF2Error::AnswerEmpty);
    }

    let answer =
      answer.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "").trim().to_string();

    let strength = zxcvbn(&answer, &[]);
    Ok(GenericFactor {
      id:     "question".to_string(),
      data:   Question { question, answer },
      params: (),
      output: strength,
    })
  }
}

#[cfg(test)]
mod tests {
  use zxcvbn::Score;

  use super::*;

  #[test]
  fn test_question_strength() {
    let question = Question::new("What is the capital of France?", "Paris");
    let factor = question.material().unwrap();
    assert_eq!(factor.output.score(), Score::Zero);
  }
}
