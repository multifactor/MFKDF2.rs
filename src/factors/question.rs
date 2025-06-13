use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")] use wasm_bindgen::prelude::*;
use zxcvbn::{Entropy, zxcvbn};

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::{Factor, FactorMaterial},
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[derive(Serialize, Deserialize)]
pub struct Question {
  question: String,
  answer:   String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl Question {
  #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
  pub fn new(question: String, answer: String) -> Question { Question { question, answer } }

  #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
  pub fn factor(self) -> MFKDF2Result<wasm_bindgen::JsValue> {
    let factor = self.into_factor()?;
    serde_wasm_bindgen::to_value(&factor).map_err(|_| MFKDF2Error::SerializeFactor)
  }
}

impl<T, U> From<(T, U)> for Question
where
  T: Into<String>,
  U: Into<String>,
{
  fn from(value: (T, U)) -> Self { Self::new(value.0.into(), value.1.into()) }
}

impl FactorMaterial for Question {
  type Output = Entropy;
  type Params = ();

  fn into_factor(self) -> MFKDF2Result<Factor<Self>> {
    let answer = self.answer;
    let question = self.question;
    if answer.is_empty() {
      return Err(MFKDF2Error::AnswerEmpty);
    }

    let answer =
      answer.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "").trim().to_string();

    let strength = zxcvbn(&answer, &[]);
    Ok(Factor {
      id:     "question".to_string(),
      data:   Self { question, answer },
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
  #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
  fn test_question_strength() {
    let question = Question::from(("What is the capital of France?", "Paris"));
    let factor = question.into_factor().unwrap();
    assert_eq!(factor.output.score(), Score::Zero);
  }
}
