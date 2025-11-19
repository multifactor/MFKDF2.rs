use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zxcvbn::zxcvbn;

use crate::{
  definitions::{FactorMetadata, FactorType, Key, MFKDF2Factor},
  error::{MFKDF2Error, MFKDF2Result},
  setup::FactorSetup,
};

/// Options for configuring a security‑question factor.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuestionOptions {
  /// Optional application-defined identifier for the factor. Defaults to `"question"`. If
  /// provided, it must be non-empty.
  pub id:       Option<String>,
  /// Human‑readable prompt shown to the user (e.g., _"What is your favorite teacher's name?"_).
  /// If omitted, you can store or render the question separately in your application.
  pub question: Option<String>,
}

impl Default for QuestionOptions {
  fn default() -> Self { Self { id: Some("question".to_string()), question: None } }
}

/// Security‑question factor state. This factor models a user-chosen security question and answer.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Question {
  /// Normalized answer string used as factor material.
  pub answer:   String,
  /// Factor public state that is used to derive the factor material.
  pub params:   Value,
  /// Human‑readable prompt shown to the user (e.g., _"What is your favorite teacher's name?"_).
  pub question: String,
}

impl FactorMetadata for Question {
  fn kind(&self) -> String { "question".to_string() }

  fn bytes(&self) -> Vec<u8> { self.answer.as_bytes().to_vec() }
}

impl FactorSetup for Question {
  type Output = Value;
  type Params = Value;

  fn params(&self, _key: Key) -> MFKDF2Result<Self::Params> {
    Ok(json!({
      "question": self.question,
    }))
  }

  fn output(&self) -> Self::Output {
    json!({
      "strength": zxcvbn(&self.answer, &[]),
    })
  }
}

/// Creates a [`Question`] factor from a raw user answer.
///
/// The `answer`` is normalized (lower‑cased, punctuation removed, surrounding whitespace trimmed)
/// to reduce accidental mismatches. Entropy is computed using `zxcvbn` on the normalized answer and
/// stored on the factor.
///
/// # Errors
/// - [`MFKDF2Error::AnswerEmpty`] if the provided answer is empty.
/// - [`MFKDF2Error::MissingFactorId`] if `options.id` is present but empty.
///
/// # Example
///
/// ```rust
/// # use mfkdf2::setup::factors::question::{question, QuestionOptions};
/// let opts = QuestionOptions {
///   id:       Some("recovery-question".into()),
///   question: Some("What is your favorite color?".into()),
/// };
/// let factor = question("Blue! No, Yellow!", opts)?;
/// assert_eq!(factor.id.as_deref(), Some("recovery-question"));
/// # Ok::<(), mfkdf2::error::MFKDF2Error>(())
/// ```
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

  let answer = answer
    .to_lowercase()
    .replace(|c: char| !c.is_alphanumeric() && !c.is_whitespace(), "")
    .trim()
    .to_string();
  let strength = zxcvbn(&answer, &[]);

  Ok(MFKDF2Factor {
    id,
    factor_type: FactorType::Question(Question { question, params: Value::Null, answer }),
    entropy: Some((strength.guesses() as f64).log2()),
  })
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn setup_question(
  answer: String,
  options: QuestionOptions,
) -> MFKDF2Result<MFKDF2Factor> {
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

    assert!(matches!(factor.factor_type, FactorType::Question(_)));
    if let FactorType::Question(q) = factor.factor_type {
      assert_eq!(q.answer, "blue no yellow");
      assert_eq!(q.question, "What is your favorite color?".to_string());
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

    let params = question_factor.params([0u8; 32].into());
    assert!(params.is_ok());
    let params = params.unwrap();
    assert!(params.is_object());
    assert_eq!(params["question"], "What is your favorite color?");
  }

  #[test]
  fn output() {
    let factor = mock_construction();
    let output = factor.factor_type.output();
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
    assert_eq!(factor.entropy.unwrap().floor(), 9.0);
  }

  #[test]
  fn answer_normalization() {
    let factor = question("  My answer is... 'Test 123!' ", QuestionOptions::default()).unwrap();
    if let FactorType::Question(q) = factor.factor_type {
      assert_eq!(q.answer, "my answer is test 123");
    } else {
      panic!("Wrong factor type");
    }
  }
}
