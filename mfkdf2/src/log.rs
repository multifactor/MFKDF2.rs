//! Logging for the MFKDF2 library.
//!
//! This module is used to initialize the logging for the library. It is enabled by the
//! `bindings` feature flag.
#![allow(unused)]

use std::str::FromStr;

type LogLevel = log::Level;

/// Logging level for MFKDF2 operations.
///
/// This enum defines the available logging levels that can be used
/// to control the verbosity of log output in the MFKDF2 library.
#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::remote(Enum))]
enum LogLevel {
  Trace,
  Debug,
  Info,
  Warn,
  Error,
}

/// Initialize logging for the MFKDF2 library.
///
/// This function sets up logging with the specified level. If no level is provided,
/// it falls back to the `RUST_LOG` environment variable, defaulting to "info" level.
///
/// # Arguments
///
/// * `level` - Optional logging level. If None, uses `RUST_LOG` env var or defaults to Info.
///
/// # Platform-specific behavior
/// On WASM targets, initializes `console_log`. On other platforms, sets the maximum log level
/// filter.
#[cfg_attr(feature = "bindings", uniffi::export)]
fn init_log(level: Option<LogLevel>) {
  // Determine log level from parameter or environment variable
  let log_level: log::Level = if let Some(level) = level {
    #[cfg(feature = "bindings")]
    match level {
      LogLevel::Trace => log::Level::Trace,
      LogLevel::Debug => log::Level::Debug,
      LogLevel::Info => log::Level::Info,
      LogLevel::Warn => log::Level::Warn,
      LogLevel::Error => log::Level::Error,
    }

    #[cfg(not(feature = "bindings"))]
    level
  } else {
    let env_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    log::Level::from_str(&env_level).unwrap_or(log::Level::Info)
  };

  #[cfg(target_arch = "wasm32")]
  let _ = console_log::init_with_level(log_level);

  log::set_max_level(log_level.to_level_filter());
}
