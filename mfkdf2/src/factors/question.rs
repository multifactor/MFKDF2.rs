use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  factors::Factor,
};

use super::FactorMaterial;
use zxcvbn::{Entropy, zxcvbn};

// TODO (autoparallel): Should this actually be like:
// pub struct Question {
//   question: String,
//   answer: String,
// }

pub struct Question(String);
impl FactorMaterial for Question {
  type Params = ();
  type Output = Entropy;

  fn material(input: Self) -> MFKDF2Result<Factor<Self>> {
    if input.0.is_empty() {
      return Err(MFKDF2Error::AnswerEmpty);
    }

    let answer = input.0;
    let cleaned_answer =
      answer.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "").trim().to_string();

    let strength = zxcvbn(&cleaned_answer, &[]);
    Ok(Factor {
      id: "question".to_string(),
      data: Self(cleaned_answer),
      params: (),
      // TODO (autoparallel): Should this not return an actual question the answer is associated to?
      output: strength,
    })
  }
}
