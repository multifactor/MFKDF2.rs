#[tokio::test]
async fn test_key_setup() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::password(
    "Tr0ubd4dour",
    Some(mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) }),
  )]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key::key(factors, Some(options)).await?;
  dbg!(key);
  Ok(())
}
