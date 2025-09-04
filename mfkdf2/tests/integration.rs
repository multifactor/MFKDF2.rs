use std::collections::HashMap;

async fn mock_derived_key()
-> Result<mfkdf2::setup::key::MFKDF2DerivedKey, mfkdf2::error::MFKDF2Error> {
  let factors = vec![mfkdf2::setup::factors::password(
    "Tr0ubd4dour",
    Some(mfkdf2::setup::factors::password::PasswordOptions { id: Some("password_1".to_string()) }),
  )]
  .into_iter()
  .collect::<Result<Vec<_>, _>>()?;

  let options = mfkdf2::setup::key::MFKDF2Options::default();
  let key = mfkdf2::setup::key::key(factors, Some(options)).await?;
  Ok(key)
}

#[tokio::test]
async fn test_key_setup() -> Result<(), mfkdf2::error::MFKDF2Error> {
  mock_derived_key().await?;
  Ok(())
}

#[tokio::test]
async fn test_key_derive() -> Result<(), mfkdf2::error::MFKDF2Error> {
  let key = mock_derived_key().await?;
  println!("Setup key: {}", key);

  let factor = ("password_1".to_owned(), mfkdf2::derive::factors::password("Tr0ubd4dour").await?);

  let factors = HashMap::from([factor]);

  let derived_key = mfkdf2::derive::key(key.policy, factors).await?;
  println!("Derived key: {}", derived_key);
  Ok(())
}
