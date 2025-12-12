use mfkdf2::prelude::*;

#[test]
fn entropy_3_of_3_passwords() -> MFKDF2Result<()> {
  // ['12345678', 'ABCDEFGH', 'abcdefgh'] with threshold 3
  let setup = setup::key(
    &[
      setup_password("12345678", PasswordOptions { id: Some("password1".to_string()) })?,
      setup_password("ABCDEFGH", PasswordOptions { id: Some("password2".to_string()) })?,
      setup_password("abcdefgh", PasswordOptions { id: Some("password3".to_string()) })?,
    ],
    MFKDF2Options { threshold: Some(3), ..Default::default() },
  )?;

  let expected_real = 4.0_f64.log2() + 33.0_f64.log2() + 33.0_f64.log2();
  assert_eq!(setup.entropy.real, expected_real);
  assert_eq!(setup.entropy.theoretical, 8 * 8 * 3);

  Ok(())
}

#[test]
fn entropy_2_of_3_passwords() -> MFKDF2Result<()> {
  let setup = setup::key(
    &[
      setup_password("12345678", PasswordOptions { id: Some("password1".to_string()) })?,
      setup_password("ABCDEFGH", PasswordOptions { id: Some("password2".to_string()) })?,
      setup_password("abcdefgh", PasswordOptions { id: Some("password3".to_string()) })?,
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )?;

  let expected_real = 4.0_f64.log2() + 33.0_f64.log2();
  assert_eq!(setup.entropy.real, expected_real);
  assert_eq!(setup.entropy.theoretical, 8 * 8 * 2);

  Ok(())
}

#[test]
fn entropy_1_of_3_passwords() -> MFKDF2Result<()> {
  let setup = setup::key(
    &[
      setup_password("12345678", PasswordOptions { id: Some("password1".to_string()) })?,
      setup_password("ABCDEFGH", PasswordOptions { id: Some("password2".to_string()) })?,
      setup_password("abcdefgh", PasswordOptions { id: Some("password3".to_string()) })?,
    ],
    MFKDF2Options { threshold: Some(1), ..Default::default() },
  )?;

  let expected_real = 4.0_f64.log2();
  assert_eq!(setup.entropy.real, expected_real);
  assert_eq!(setup.entropy.theoretical, (8 * 8));

  Ok(())
}

#[test]
fn entropy_policy_combinators() -> MFKDF2Result<()> {
  // Mirrors the complex AND/OR/ANY nesting from the JS test
  let policy = policy::setup(
    policy::and(
      setup_password("12345678", PasswordOptions { id: Some("password1".to_string()) })?,
      policy::any(vec![
        setup_password("12345678", PasswordOptions { id: Some("password7".to_string()) })?,
        policy::or(
          setup_password("12345678", PasswordOptions { id: Some("password3".to_string()) })?,
          setup_password("12345678", PasswordOptions { id: Some("password2".to_string()) })?,
        )?,
        policy::and(
          setup_password("12345678", PasswordOptions { id: Some("password4".to_string()) })?,
          policy::or(
            setup_password("12345678", PasswordOptions { id: Some("password5".to_string()) })?,
            setup_password("12345678", PasswordOptions { id: Some("password6".to_string()) })?,
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
fn entropy_totp_hotp_6_digits() -> MFKDF2Result<()> {
  let setup = setup::key(
    &[
      setup_totp(Default::default())?, // default 6 digits
      setup_hotp(Default::default())?, // default 6 digits
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )?;

  let expected_real = 10f64.powi(6).log2() * 2.0;
  assert_eq!(setup.entropy.real, expected_real);

  Ok(())
}

#[test]
fn entropy_totp_hotp_8_digits() -> MFKDF2Result<()> {
  let setup = setup::key(
    &[
      setup_totp(TOTPOptions { digits: Some(8), ..Default::default() })?,
      setup_hotp(HOTPOptions { digits: Some(8), ..Default::default() })?,
    ],
    MFKDF2Options { threshold: Some(2), ..Default::default() },
  )?;

  let expected_real = 10f64.powi(8).log2() * 2.0;
  assert_eq!(setup.entropy.real, expected_real);

  Ok(())
}
