use mfkdf2::{
  policy::setup::PolicySetupOptions,
  setup::{factors::password::PasswordOptions, key::MFKDF2Options},
};

#[test]
fn entropy_3_of_3_passwords() -> Result<(), mfkdf2::error::MFKDF2Error> {
  // ['12345678', 'ABCDEFGH', 'abcdefgh'] with threshold 3
  let setup = mfkdf2::setup::key(
    &[
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

  let expected_real = 4.0_f64.log2() + 33.0_f64.log2() + 33.0_f64.log2();
  assert_eq!(setup.entropy.real, expected_real);
  assert_eq!(setup.entropy.theoretical, 8 * 8 * 3);

  Ok(())
}

#[test]
fn entropy_2_of_3_passwords() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let setup = mfkdf2::setup::key(
    &[
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

  let expected_real = 4.0_f64.log2() + 33.0_f64.log2();
  assert_eq!(setup.entropy.real, expected_real);
  assert_eq!(setup.entropy.theoretical, 8 * 8 * 2);

  Ok(())
}

#[test]
fn entropy_1_of_3_passwords() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let setup = mfkdf2::setup::key(
    &[
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

  let expected_real = 4.0_f64.log2();
  assert_eq!(setup.entropy.real, expected_real);
  assert_eq!(setup.entropy.theoretical, (8 * 8));

  Ok(())
}

#[test]
fn entropy_policy_combinators() -> Result<(), mfkdf2::error::MFKDF2Error> {
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
        )?,
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
          )?,
        )?,
      ])?,
    )?,
    PolicySetupOptions::default(),
  )?;

  let expected_real = 4.0_f64.log2() * 2.0;
  assert_eq!(policy.entropy.real, expected_real);

  Ok(())
}

#[test]
fn entropy_totp_hotp_6_digits() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let setup = mfkdf2::setup::key(
    &[
      mfkdf2::setup::factors::totp(Default::default())?, // default 6 digits
      mfkdf2::setup::factors::hotp(Default::default())?, // default 6 digits
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )?;

  let expected_real = 10f64.powi(6).log2() * 2.0;
  assert_eq!(setup.entropy.real, expected_real);

  Ok(())
}

#[test]
fn entropy_totp_hotp_8_digits() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let setup = mfkdf2::setup::key(
    &[
      mfkdf2::setup::factors::totp(mfkdf2::setup::factors::totp::TOTPOptions {
        digits: Some(8),
        ..Default::default()
      })?,
      mfkdf2::setup::factors::hotp(mfkdf2::setup::factors::hotp::HOTPOptions {
        digits: 8,
        ..Default::default()
      })?,
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )?;

  let expected_real = 10f64.powi(8).log2() * 2.0;
  assert_eq!(setup.entropy.real, expected_real);

  Ok(())
}
