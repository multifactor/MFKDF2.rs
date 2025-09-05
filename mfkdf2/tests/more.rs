// #[cfg(test)]
// mod tests {
//   #![allow(clippy::unwrap_used)]
//   #![allow(clippy::expect_used)]
//   #![allow(clippy::type_complexity)]

//   use itertools::Itertools;
//   use rstest::{fixture, rstest};

//   use super::*;
//   use crate::setup::factors::{
//     Setup,
//     hotp::{HOTP, HOTPOptions},
//     password::Password,
//     question::Question,
//     uuid::Uuid,
//   };

//   #[fixture]
//   fn all_factors() -> Vec<Material> {
//     let mut p: Material = Password::new("hunter2").unwrap().into();
//     p.set_id("pw");
//     let mut q: Material = Question::new("What is the capital of France?",
// "Paris").unwrap().into();     q.set_id("qa");
//     let mut u: Material = Uuid::from_u128(123_456_789_012).into();
//     u.set_id("id");
//     vec![p, q, u]
//   }

//   #[fixture]
//   fn policy_1(all_factors: Vec<Material>) -> (Policy, [u8; 32], u32, u32) {
//     PolicyBuilder::new()
//       .with_threshold(1)
//       .with_factor(all_factors[0].clone())
//       .with_factor(all_factors[1].clone())
//       .with_factor(all_factors[2].clone())
//       .build()
//       .unwrap()
//   }

//   #[fixture]
//   fn policy_2(all_factors: Vec<Material>) -> (Policy, [u8; 32], u32, u32) {
//     PolicyBuilder::new()
//       .with_threshold(2)
//       .with_factor(all_factors[0].clone())
//       .with_factor(all_factors[1].clone())
//       .with_factor(all_factors[2].clone())
//       .build()
//       .unwrap()
//   }

//   #[fixture]
//   fn policy_3(all_factors: Vec<Material>) -> (Policy, [u8; 32], u32, u32) {
//     PolicyBuilder::new()
//       .with_threshold(3)
//       .with_factor(all_factors[0].clone())
//       .with_factor(all_factors[1].clone())
//       .with_factor(all_factors[2].clone())
//       .build()
//       .unwrap()
//   }

//   fn subsets(src: &[Material], k: usize) -> impl Iterator<Item = Vec<Material>> {
//     (0..src.len()).combinations(k).map(|idx| idx.into_iter().map(|i| src[i].clone()).collect())
//   }

//   #[rstest]
//   fn generates_policy(policy_3: (Policy, [u8; 32], u32, u32)) {
//     let (p, ..) = policy_3;
//     assert_eq!(p.threshold, 3);
//     assert_eq!(p.factors.len(), 3);
//   }

//   #[rstest]
//   fn round_trip(policy_3: (Policy, [u8; 32], u32, u32), all_factors: Vec<Material>) {
//     let (p, key, ..) = policy_3;
//     assert_eq!(p.derive(all_factors).unwrap(), key);
//   }

//   #[rstest]
//   #[case::policy_1_k_0(policy_1, 0)]
//   #[case::policy_2_k_0(policy_2, 0)]
//   #[case::policy_2_k_1(policy_2, 1)]
//   #[case::policy_3_k_0(policy_3, 0)]
//   #[case::policy_3_k_1(policy_3, 1)]
//   #[case::policy_3_k_2(policy_3, 2)]
//   fn insufficient(
//     #[case] policy: fn(Vec<Material>) -> (Policy, [u8; 32], u32, u32),
//     #[case] k: usize,
//     all_factors: Vec<Material>,
//   ) {
//     let (p, ..) = policy(all_factors.clone());
//     for s in subsets(&all_factors, k) {
//       assert_eq!(p.derive(s).unwrap_err().to_string(),
// MFKDF2Error::ShareRecoveryError.to_string());     }
//   }

//   #[rstest]
//   #[case::policy_1(policy_1, 1)]
//   #[case::policy_2(policy_2, 2)]
//   #[case::policy_3(policy_3, 3)]
//   fn threshold(
//     #[case] policy: fn(Vec<Material>) -> (Policy, [u8; 32], u32, u32),
//     #[case] k: usize,
//     all_factors: Vec<Material>,
//   ) {
//     let (p, key, ..) = policy(all_factors.clone());
//     for s in subsets(&all_factors, k) {
//       assert_eq!(p.derive(s).unwrap(), key);
//     }
//   }

//   #[rstest]
//   #[case::policy_1(policy_1, 9, 40)]
//   #[case::policy_2(policy_2, 21, 96)]
//   #[case::policy_3(policy_3, 143, 256)]
//   fn entropy(
//     #[case] policy: fn(Vec<Material>) -> (Policy, [u8; 32], u32, u32),
//     #[case] entropy_real: u32,
//     #[case] entropy_theoretical: u32,
//     all_factors: Vec<Material>,
//   ) {
//     let (_, _, computed_entropy_real, computed_entropy_theoretical) = policy(all_factors);
//     assert_eq!(entropy_real, computed_entropy_real);
//     assert_eq!(entropy_theoretical, computed_entropy_theoretical);
//   }

//   #[test]
//   fn test_hotp_factor_with_policy() {
//     // Test that HOTP factor works with the Setup trait
//     let hotp_options = HOTPOptions {
//       id: Some("hotp".to_string()),
//       secret: Some(b"test secret".to_vec()),
//       digits: 6,
//       ..Default::default()
//     };

//     let mut hotp_material = HOTP::setup(hotp_options).unwrap();
//     hotp_material.set_id("hotp");

//     // Create a policy with HOTP factor
//     let (policy, _key, _entropy_real, _entropy_theoretical) =
//       PolicyBuilder::new().with_threshold(1).with_factor(hotp_material).build().unwrap();

//     assert_eq!(policy.threshold, 1);
//     assert_eq!(policy.factors.len(), 1);
//     assert_eq!(policy.factors[0].kind, "hotp");
//     assert_eq!(policy.factors[0].id, "hotp");
//   }
// }
