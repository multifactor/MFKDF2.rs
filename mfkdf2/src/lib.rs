#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();

pub mod constants;
pub mod crypto;
pub mod definitions;
pub mod derive;
pub mod error;
pub mod integrity;
pub mod policy;
pub mod rng;
pub mod setup;

type LogLevel = log::Level;

#[cfg(feature = "bindings")]
#[cfg_attr(feature = "bindings", uniffi::remote(Enum))]
enum LogLevel {
  Trace,
  Debug,
  Info,
  Warn,
  Error,
}

#[cfg_attr(feature = "bindings", uniffi::export)]
pub async fn init_rust_logging(level: Option<LogLevel>) {
  // Determine log level from parameter or environment variable
  #[cfg(feature = "bindings")]
  let log_level: log::Level = if let Some(level) = level {
    match level {
      LogLevel::Trace => log::Level::Trace,
      LogLevel::Debug => log::Level::Debug,
      LogLevel::Info => log::Level::Info,
      LogLevel::Warn => log::Level::Warn,
      LogLevel::Error => log::Level::Error,
    }
  } else {
    let env_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    match env_level.to_lowercase().as_str() {
      "trace" => log::Level::Trace,
      "debug" => log::Level::Debug,
      "info" => log::Level::Info,
      "warn" => log::Level::Warn,
      "error" => log::Level::Error,
      _ => log::Level::Info,
    }
  };

  #[cfg(not(feature = "bindings"))]
  let log_level = if let Some(level) = level {
    level
  } else {
    let env_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    match env_level.to_lowercase().as_str() {
      "trace" => log::Level::Trace,
      "debug" => log::Level::Debug,
      "info" => log::Level::Info,
      "warn" => log::Level::Warn,
      "error" => log::Level::Error,
      _ => log::Level::Info,
    }
  };

  #[cfg(target_arch = "wasm32")]
  let _ = console_log::init_with_level(log_level);

  log::set_max_level(log_level.to_level_filter());
}
