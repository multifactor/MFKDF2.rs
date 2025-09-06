use std::{
  ffi::{CStr, CString},
  os::raw::c_char,
  ptr,
};

// Memory management for passing strings between WASM and JS
#[unsafe(no_mangle)]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
  let mut buf = Vec::with_capacity(size);
  let ptr = buf.as_mut_ptr();
  std::mem::forget(buf);
  ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
  unsafe {
    let _ = Vec::from_raw_parts(ptr, 0, size);
  }
}

// Helper function to convert C string to Rust string
unsafe fn c_str_to_string(ptr: *const c_char) -> Result<String, String> {
  if ptr.is_null() {
    return Err("Null pointer".to_string());
  }

  unsafe {
    match CStr::from_ptr(ptr).to_str() {
      Ok(s) => Ok(s.to_string()),
      Err(_) => Err("Invalid UTF-8".to_string()),
    }
  }
}

// Helper function to convert Rust string to C string (caller must free)
fn string_to_c_str(s: String) -> *mut c_char {
  match CString::new(s) {
    Ok(c_string) => c_string.into_raw(),
    Err(_) => ptr::null_mut(),
  }
}

// Simple test function
#[unsafe(no_mangle)]
pub extern "C" fn test_function(input_ptr: *const c_char) -> *mut c_char {
  unsafe {
    let input = match c_str_to_string(input_ptr) {
      Ok(s) => s,
      Err(_) => return ptr::null_mut(),
    };

    let result = format!("Hello from WASM! You said: {}", input);
    string_to_c_str(result)
  }
}

// Create a simple password factor (without async for now)
#[unsafe(no_mangle)]
pub extern "C" fn create_password_factor(
  password_ptr: *const c_char,
  id_ptr: *const c_char,
) -> *mut c_char {
  unsafe {
    let password = match c_str_to_string(password_ptr) {
      Ok(s) => s,
      Err(_) => return ptr::null_mut(),
    };

    let id = if id_ptr.is_null() {
      "password".to_string()
    } else {
      match c_str_to_string(id_ptr) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
      }
    };

    // Simple entropy calculation (just password length for now)
    let entropy = password.len() * 4; // rough estimate

    let factor_json = serde_json::json!({
        "type": "password",
        "id": id,
        "entropy": entropy,
        "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, password.as_bytes())
    });

    match serde_json::to_string(&factor_json) {
      Ok(json) => string_to_c_str(json),
      Err(_) => ptr::null_mut(),
    }
  }
}

// Free a C string allocated by this module
#[unsafe(no_mangle)]
pub extern "C" fn free_string(ptr: *mut c_char) {
  if !ptr.is_null() {
    unsafe {
      let _ = CString::from_raw(ptr);
    }
  }
}
