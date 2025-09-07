use mfkdf2::setup::factors::password::PasswordOptions;
use wasm_bindgen::prelude::*;

// Initialize panic hook for better error messages
#[wasm_bindgen(start)]
pub fn main() { console_error_panic_hook::set_once(); }

/// Test function to make sure basic string return works
#[wasm_bindgen]
pub fn test_string_return() -> String { "Hello from WASM!".to_string() }

/// Very thin wrapper around mfkdf2::setup::factors::password::password
/// Just handles the JS/WASM boundary and returns JSON
#[wasm_bindgen]
pub fn setup_factors_password(password: String, id: Option<String>) -> String {
  let options = PasswordOptions { id };

  match mfkdf2::setup::factors::password::password(password, options) {
    Ok(factor) => match serde_json::to_string(&factor) {
      Ok(json) => json,
      Err(e) => format!("{{\"error\": \"JSON serialization error: {:?}\"}}", e),
    },
    Err(e) => format!("{{\"error\": \"Failed to create password factor: {:?}\"}}", e),
  }
}

/// Very thin wrapper around mfkdf2::setup::key::key
/// Takes factors JSON and options JSON, returns derived key JSON
#[wasm_bindgen]
pub async fn setup_key(factors_json: String, options_json: Option<String>) -> String {
  // Parse factors from JSON
  let factors: Vec<mfkdf2::setup::factors::MFKDF2Factor> = match serde_json::from_str(&factors_json)
  {
    Ok(factors) => factors,
    Err(e) => return format!("{{\"error\": \"Failed to parse factors JSON: {:?}\"}}", e),
  };

  // Parse options from JSON or use default
  let options: mfkdf2::setup::key::MFKDF2Options = match options_json {
    Some(json) => match serde_json::from_str(&json) {
      Ok(options) => options,
      Err(e) => return format!("{{\"error\": \"Failed to parse options JSON: {:?}\"}}", e),
    },
    None => mfkdf2::setup::key::MFKDF2Options::default(),
  };

  // Call the actual setup::key function
  match mfkdf2::setup::key::key(factors, options).await {
    Ok(derived_key) => match serde_json::to_string(&derived_key) {
      Ok(json) => json,
      Err(e) => format!("{{\"error\": \"JSON serialization error: {:?}\"}}", e),
    },
    Err(e) => format!("{{\"error\": \"Failed to create key: {:?}\"}}", e),
  }
}

/// Very thin wrapper around mfkdf2::derive::key::key
/// Takes policy JSON and factors JSON, returns derived key JSON
#[wasm_bindgen]
pub async fn derive_key(policy_json: String, factors_json: String) -> String {
  // Parse policy from JSON
  let policy: mfkdf2::setup::key::Policy = match serde_json::from_str(&policy_json) {
    Ok(policy) => policy,
    Err(e) => return format!("{{\"error\": \"Failed to parse policy JSON: {:?}\"}}", e),
  };

  // Parse factors from JSON - expecting HashMap<String, MFKDF2Factor>
  let factors: std::collections::HashMap<String, mfkdf2::setup::factors::MFKDF2Factor> =
    match serde_json::from_str(&factors_json) {
      Ok(factors) => factors,
      Err(e) => return format!("{{\"error\": \"Failed to parse factors JSON: {:?}\"}}", e),
    };

  // Call the actual derive::key function
  match mfkdf2::derive::key::key(policy, factors).await {
    Ok(derived_key) => match serde_json::to_string(&derived_key) {
      Ok(json) => json,
      Err(e) => format!("{{\"error\": \"JSON serialization error: {:?}\"}}", e),
    },
    Err(e) => format!("{{\"error\": \"Failed to derive key: {:?}\"}}", e),
  }
}

/// Very thin wrapper around mfkdf2::derive::factors::password::password
/// Just handles the JS/WASM boundary and returns JSON
#[wasm_bindgen]
pub fn derive_factors_password(password: String) -> String {
  match mfkdf2::derive::factors::password::password(password) {
    Ok(factor) => match serde_json::to_string(&factor) {
      Ok(json) => json,
      Err(e) => format!("{{\"error\": \"JSON serialization error: {:?}\"}}", e),
    },
    Err(e) => format!("{{\"error\": \"Failed to create derive password factor: {:?}\"}}", e),
  }
}
