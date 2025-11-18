use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use mfkdf2::{
  derive,
  setup::{
    self,
    factors::question::{QuestionOptions, question as setup_question},
    key::MFKDF2Options,
  },
};

fn bench_question(c: &mut Criterion) {
  let mut group = c.benchmark_group("question");
  // Single setup - 1 question
  group.bench_function("single_setup", |b| {
    b.iter(|| {
      let factor = black_box(
        setup_question("answer1", QuestionOptions {
          id:       Some("question".to_string()),
          question: Some("What is your favorite color?".to_string()),
        })
        .unwrap(),
      );
      let result = black_box(setup::key::key(&[factor], MFKDF2Options::default()));
      result.unwrap()
    })
  });

  // Single derive - 1 question
  let single_setup_key = setup::key::key(
    &[setup_question("answer1", QuestionOptions {
      id:       Some("question".to_string()),
      question: Some("What is your favorite color?".to_string()),
    })
    .unwrap()],
    MFKDF2Options::default(),
  )
  .unwrap();

  group.bench_function("single_derive", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([(
        "question".to_string(),
        derive::factors::question("answer1").unwrap(),
      )]));
      let result = black_box(derive::key(&single_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Multiple setup - 3 questions with threshold 3 (all required)
  group.bench_function("multiple_setup_3_threshold_3", |b| {
    b.iter(|| {
      let options = MFKDF2Options { threshold: Some(3), ..Default::default() };
      let result = black_box(setup::key::key(
        &[
          setup_question("answer1", QuestionOptions {
            id:       Some("q1".to_string()),
            question: Some("What is your favorite color?".to_string()),
          })
          .unwrap(),
          setup_question("answer2", QuestionOptions {
            id:       Some("q2".to_string()),
            question: Some("What is your pet's name?".to_string()),
          })
          .unwrap(),
          setup_question("answer3", QuestionOptions {
            id:       Some("q3".to_string()),
            question: Some("What is your mother's maiden name?".to_string()),
          })
          .unwrap(),
        ],
        options,
      ));
      result.unwrap()
    })
  });

  // Multiple derive - 3 questions (all required)
  let multiple_setup_key_3 = setup::key::key(
    &[
      setup_question("answer1", QuestionOptions {
        id:       Some("q1".to_string()),
        question: Some("What is your favorite color?".to_string()),
      })
      .unwrap(),
      setup_question("answer2", QuestionOptions {
        id:       Some("q2".to_string()),
        question: Some("What is your pet's name?".to_string()),
      })
      .unwrap(),
      setup_question("answer3", QuestionOptions {
        id:       Some("q3".to_string()),
        question: Some("What is your mother's maiden name?".to_string()),
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )
  .unwrap();

  group.bench_function("multiple_derive_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("q1".to_string(), derive::factors::question("answer1").unwrap()),
        ("q2".to_string(), derive::factors::question("answer2").unwrap()),
        ("q3".to_string(), derive::factors::question("answer3").unwrap()),
      ]));
      let result = black_box(derive::key(&multiple_setup_key_3.policy, factors_map, false, false));
      result.unwrap()
    })
  });

  // Threshold derive - 2 out of 3 questions
  let threshold_setup_key = setup::key::key(
    &[
      setup_question("answer1", QuestionOptions {
        id:       Some("q1".to_string()),
        question: Some("What is your favorite color?".to_string()),
      })
      .unwrap(),
      setup_question("answer2", QuestionOptions {
        id:       Some("q2".to_string()),
        question: Some("What is your pet's name?".to_string()),
      })
      .unwrap(),
      setup_question("answer3", QuestionOptions {
        id:       Some("q3".to_string()),
        question: Some("What is your mother's maiden name?".to_string()),
      })
      .unwrap(),
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )
  .unwrap();

  group.bench_function("threshold_derive_2_of_3", |b| {
    b.iter(|| {
      let factors_map = black_box(HashMap::from([
        ("q1".to_string(), derive::factors::question("answer1").unwrap()),
        ("q2".to_string(), derive::factors::question("answer2").unwrap()),
      ]));
      let result = black_box(derive::key(&threshold_setup_key.policy, factors_map, false, false));
      result.unwrap()
    })
  });
}

criterion_group!(question_bench, bench_question);
criterion_main!(question_bench);
