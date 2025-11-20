//! Derive phase [Question](`crate::setup::factors::question`) construction. It accepts a raw user
//! answer, normalizes it, and returns an [`MFKDF2Factor`] used in the derive phase. The factor also
//! exposes a strength estimate via `output()` so callers can compare entropy between setup and
//! derive
use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  definitions::{FactorType, Key, MFKDF2Factor},
  derive::FactorDerive,
  error::{MFKDF2Error, MFKDF2Result},
  setup::factors::question::Question,
};

impl FactorDerive for Question {
  type Output = Value;
  type Params = Value;

  fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()> {
    self.params = params;
    Ok(())
  }

  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> { Ok(self.params.clone()) }

  /// Returns a strength estimate for the answer using `zxcvbn`.
  fn output(&self) -> Self::Output { json!({"strength": zxcvbn(&self.answer, &[])}) }
}

/// Factor construction derive phase for a security‑question factor
///
/// The answer is normalized (lower‑cased, punctuation removed, and surrounding whitespace trimmed)
/// to match the behaviour of the setup‑time [question](`crate::setup::factors::question::question`)
/// helper. The resulting [`MFKDF2Factor`] has no id or entropy assigned during the derive phase;
/// those are pulled from the policy when combining factors with [`crate::derive::key`]
///
/// # Errors
///
/// - [`MFKDF2Error::AnswerEmpty`] if the provided answer is empty
///
/// # Example
///
/// Single‑factor setup/derive using a security‑question factor within KeySetup/KeyDerive:
///
/// ```rust
/// # use std::collections::HashMap;
/// # use mfkdf2::{
/// #   error::MFKDF2Result,
/// #   setup::{
/// #     self,
/// #     factors::question::{QuestionOptions, question as setup_question},
/// #     key::MFKDF2Options,
/// #   },
/// #   derive,
/// # };
/// # use mfkdf2::derive::factors::question as derive_question;
/// #
/// # fn main() -> MFKDF2Result<()> {
/// let setup_factor = setup_question("Blue! Is My Favorite Color.", QuestionOptions {
///   id:       Some("question".into()),
///   question: Some("prompt".into()),
/// })?;
/// let setup_key = setup::key(&[setup_factor], MFKDF2Options::default())?;
///
/// let derive_factor = derive_question("  Blue! Is My Favorite Color.  ")?;
/// let derived_key = derive::key(
///   &setup_key.policy,
///   HashMap::from([("question".to_string(), derive_factor)]),
///   true,
///   false,
/// )?;
///
/// assert_eq!(derived_key.key, setup_key.key);
/// # Ok(())
/// # }
/// ```
pub fn question(answer: impl Into<String>) -> MFKDF2Result<MFKDF2Factor> {
  let answer = answer.into();
  if answer.is_empty() {
    return Err(MFKDF2Error::AnswerEmpty);
  }
  let answer = answer
    .to_lowercase()
    .replace(|c: char| !c.is_alphanumeric() && !c.is_whitespace(), "")
    .trim()
    .to_string();

  Ok(MFKDF2Factor {
    id:          None,
    // TODO (@lonerapier): MaybeUninit is a better type here that is initialised at
    // [`crate::derive::FactorDeriveTrait::include_params`]
    factor_type: FactorType::Question(Question {
      question: String::new(),
      params: Value::Null,
      answer,
    }),
    entropy:     None,
  })
}

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::export)]
async fn derive_question(answer: String) -> MFKDF2Result<MFKDF2Factor> { question(answer) }

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
      assert_eq!(q.answer, "blue is my favorite color");
    } else {
      panic!("Wrong factor type");
    }
  }

  #[test]
  fn include_and_derive_params() {
    // 1. Setup a factor to get setup_params
    let setup_factor = mock_question_setup();
    let setup_params = setup_factor.factor_type.setup().params([0u8; 32].into()).unwrap();

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
    let stored_params = question_struct.params.clone();
    assert_eq!(stored_params, setup_params);

    // 6. Call params_derive and check if it returns the same params
    let derived_params = question_struct.params([0u8; 32].into()).unwrap();
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
