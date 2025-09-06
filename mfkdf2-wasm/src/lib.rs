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
