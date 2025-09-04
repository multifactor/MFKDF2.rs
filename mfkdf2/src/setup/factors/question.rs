use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use zxcvbn::zxcvbn;

use crate::{
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::MFKDF2Factor,
};

pub struct QuestionOptions {
  pub id:       Option<String>,
  pub question: String,
}

pub fn question(
  answer: impl Into<String>,
  options: Option<QuestionOptions>,
) -> MFKDF2Result<MFKDF2Factor> {
  let answer = answer.into();
  if answer.is_empty() {
    return Err(MFKDF2Error::AnswerEmpty);
  }
  let answer = answer.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "").trim().to_string();
  let strength = zxcvbn(&answer, &[]);
  let entropy = strength.guesses().ilog2();

  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  let (id, question_text) = match options {
    Some(opts) => (opts.id.unwrap_or("question".to_string()), opts.question),
    None => ("question".to_string(), String::new()),
  };

  Ok(MFKDF2Factor {
    kind: "question".to_string(),
    id,
    data: answer.as_bytes().to_vec(),
    salt,
    params: Some(Box::new(move || {
      let q = question_text.clone();
      Box::pin(async move { json!({ "question": q }) })
    })),
    entropy: Some(entropy),
    output: None,
  })
}

#[cfg(test)]
mod tests {

  use super::*;

  #[test]
  fn test_question_strength() {
    let factor = question(
      "Paris",
      Some(QuestionOptions {
        id:       None,
        question: "What is the capital of France?".to_string(),
      }),
    )
    .unwrap();
    assert_eq!(factor.entropy, Some(9));
  }
}
