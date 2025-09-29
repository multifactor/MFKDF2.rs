use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::{
    FactorType, MFKDF2Factor,
    question::{Question, QuestionOptions},
  },
};

impl FactorDerive for Question {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.params = serde_json::to_string(&params).unwrap();
    Ok(())
  }

  fn params(&self, _key: [u8; 32]) -> Value { serde_json::from_str(&self.params).unwrap() }

  fn output(&self) -> Value { json!({"strength": zxcvbn(&self.answer, &[])}) }
}

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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::setup::factors::question as setup_question;

  fn mock_question_setup() -> MFKDF2Factor {
    let options = setup_question::QuestionOptions {
      id:       Some("test-question".to_string()),
      question: Some("What is your favorite color?".to_string()),
    };
    let result = setup_question::question("blue", options);
    assert!(result.is_ok());
    result.unwrap()
  }

  #[test]
  fn question_ok() {
    let result = question("blue");
    assert!(result.is_ok());
    let factor = result.unwrap();
    if let FactorType::Question(q) = factor.factor_type {
      assert_eq!(q.answer, "blue");
    } else {
      panic!("Wrong factor type");
    }
  }

  #[test]
  fn empty_answer() {
    let result = question("");
    assert!(matches!(result, Err(MFKDF2Error::AnswerEmpty)));
  }

  #[test]
  fn normalization() {
    let result = question("  Blue! Is My Favorite Color.  ");
    assert!(result.is_ok());
    let factor = result.unwrap();
    if let FactorType::Question(q) = factor.factor_type {
      assert_eq!(q.answer, "blueismyfavoritecolor");
    } else {
      panic!("Wrong factor type");
    }
  }

  #[test]
  fn include_and_derive_params() {
    // 1. Setup a factor to get setup_params
    let setup_factor = mock_question_setup();
    let setup_params = setup_factor.factor_type.setup().params([0u8; 32]);

    // 2. Create a derive factor
    let derive_factor_result = question("my answer");
    assert!(derive_factor_result.is_ok());
    let mut derive_factor = derive_factor_result.unwrap();

    // 3. Call include_params
    let result = derive_factor.factor_type.include_params(setup_params.clone());
    assert!(result.is_ok());

    // 4. Get the inner Question struct
    let question_struct = match derive_factor.factor_type {
      FactorType::Question(q) => q,
      _ => panic!("Wrong factor type"),
    };

    // 5. Check that params were stored
    let stored_params: Value = serde_json::from_str(&question_struct.params).unwrap();
    assert_eq!(stored_params, setup_params);

    // 6. Call params_derive and check if it returns the same params
    let derived_params = question_struct.params([0u8; 32]);
    assert_eq!(derived_params, setup_params);
  }

  #[test]
  fn output_derive() {
    let result = question("password123");
    assert!(result.is_ok());
    let factor = result.unwrap();
    let question_struct = match factor.factor_type {
      FactorType::Question(q) => q,
      _ => panic!("Wrong factor type"),
    };

    let output = question_struct.output();
    assert!(output.is_object());
    assert!(output["strength"].is_object());
    let score = output["strength"]["score"].as_u64();
    assert!(score.is_some());
    // zxcvbn score for "password123" is low
    assert!(score.unwrap() <= 2);
  }
}
