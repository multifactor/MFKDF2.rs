use mfkdf2::{
  policy::setup::PolicySetupOptions,
  setup::{factors::password::PasswordOptions, key::MFKDF2Options},
};

fn floor_log2(x: f64) -> i64 { x.log2().floor() as i64 }

#[test]
fn entropy_3_of_3_passwords() -> Result<(), mfkdf2::error::MFKDF2Error> {
  // ['12345678', 'ABCDEFGH', 'abcdefgh'] with threshold 3
  let setup = mfkdf2::setup::key(
    vec![
      mfkdf2::setup::factors::password("12345678", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      mfkdf2::setup::factors::password("ABCDEFGH", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      mfkdf2::setup::factors::password("abcdefgh", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )?;

  // Expected: floor(log2(4) + log2(33) + log2(33)) and theoretical = 8*8*3
  let expected_real = floor_log2(4.0) + floor_log2(33.0) + floor_log2(33.0);
  assert_eq!(setup.entropy.real, expected_real as u32);
  assert_eq!(setup.entropy.theoretical, 8 * 8 * 3);

  Ok(())
}

#[test]
fn entropy_2_of_3_passwords() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let setup = mfkdf2::setup::key(
    vec![
      mfkdf2::setup::factors::password("12345678", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      mfkdf2::setup::factors::password("ABCDEFGH", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      mfkdf2::setup::factors::password("abcdefgh", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )?;

  // Expected: floor(log2(4) + log2(33)) and theoretical = 8*8*2
  let expected_real = floor_log2(4.0) + floor_log2(33.0);
  assert_eq!(setup.entropy.real, expected_real as u32);
  assert_eq!(setup.entropy.theoretical, 8 * 8 * 2);

  Ok(())
}

#[test]
fn entropy_1_of_3_passwords() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let setup = mfkdf2::setup::key(
    vec![
      mfkdf2::setup::factors::password("12345678", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      mfkdf2::setup::factors::password("ABCDEFGH", PasswordOptions {
        id: Some("password2".to_string()),
      })?,
      mfkdf2::setup::factors::password("abcdefgh", PasswordOptions {
        id: Some("password3".to_string()),
      })?,
    ],
    MFKDF2Options { threshold: Some(1), ..Default::default() },
  )?;

  // Expected: floor(log2(4)) and theoretical = 8*8*1
  let expected_real = floor_log2(4.0);
  assert_eq!(setup.entropy.real, expected_real as u32);
  assert_eq!(setup.entropy.theoretical, (8 * 8));

  Ok(())
}

#[tokio::test]
async fn entropy_policy_combinators() -> Result<(), mfkdf2::error::MFKDF2Error> {
  // Mirrors the complex AND/OR/ANY nesting from the JS test
  let policy = mfkdf2::policy::setup::setup(
    mfkdf2::policy::logic::and(
      mfkdf2::setup::factors::password("12345678", PasswordOptions {
        id: Some("password1".to_string()),
      })?,
      mfkdf2::policy::logic::any(vec![
        mfkdf2::setup::factors::password("12345678", PasswordOptions {
          id: Some("password7".to_string()),
        })?,
        mfkdf2::policy::logic::or(
          mfkdf2::setup::factors::password("12345678", PasswordOptions {
            id: Some("password3".to_string()),
          })?,
          mfkdf2::setup::factors::password("12345678", PasswordOptions {
            id: Some("password2".to_string()),
          })?,
        )
        .await?,
        mfkdf2::policy::logic::and(
          mfkdf2::setup::factors::password("12345678", PasswordOptions {
            id: Some("password4".to_string()),
          })?,
          mfkdf2::policy::logic::or(
            mfkdf2::setup::factors::password("12345678", PasswordOptions {
              id: Some("password5".to_string()),
            })?,
            mfkdf2::setup::factors::password("12345678", PasswordOptions {
              id: Some("password6".to_string()),
            })?,
          )
          .await?,
        )
        .await?,
      ])
      .await?,
    )
    .await?,
    PolicySetupOptions::default(),
  )?;

  // Expected: floor(log2(4) * 2)
  let expected_real = floor_log2(4.0 * 4.0); // same as floor(Math.log2(4) * 2)
  assert_eq!(policy.entropy.real, expected_real as u32);

  Ok(())
}

#[test]
fn entropy_totp_hotp_6_digits() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let setup = mfkdf2::setup::key(
    vec![
      mfkdf2::setup::factors::totp(Default::default())?, // default 6 digits
      mfkdf2::setup::factors::hotp(Default::default())?, // default 6 digits
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )?;

  // Expected: floor(log2(10 ** 6) * 2)
  let expected_real = ((10f64.powi(6)).log2() * 2.0).floor();
  assert_eq!(setup.entropy.real, expected_real as u32);

  Ok(())
}

#[test]
fn entropy_totp_hotp_8_digits() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let setup = mfkdf2::setup::key(
    vec![
      mfkdf2::setup::factors::totp(mfkdf2::setup::factors::totp::TOTPOptions {
        digits: 8,
        ..Default::default()
      })?,
      mfkdf2::setup::factors::hotp(mfkdf2::setup::factors::hotp::HOTPOptions {
        digits: 8,
        ..Default::default()
      })?,
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )?;

  // Expected: floor(log2(10 ** 8) * 2)
  let expected_real = ((10f64.powi(8)).log2() * 2.0).floor();
  assert_eq!(setup.entropy.real, expected_real as u32);

  Ok(())
}
