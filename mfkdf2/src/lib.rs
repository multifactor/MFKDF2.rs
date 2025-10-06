uniffi::setup_scaffolding!();

pub mod crypto;
pub mod definitions;
pub mod derive;
pub mod error;
pub mod integrity;
pub mod policy;
pub mod setup;

type LogLevel = log::Level;

#[uniffi::remote(Enum)]
enum LogLevel {
  Trace,
  Debug,
  Info,
  Warn,
  Error,
}

#[uniffi::export]
pub async fn init_rust_logging(level: Option<LogLevel>) {
  // Determine log level from parameter or environment variable
  let log_level = if let Some(level) = level {
    level
  } else {
    // Fall back to environment variable or default
    let env_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    match env_level.to_lowercase().as_str() {
      "trace" => log::Level::Trace,
      "debug" => log::Level::Debug,
      "info" => log::Level::Info,
      "warn" => log::Level::Warn,
      "error" => log::Level::Error,
      _ => log::Level::Info, // default to info if invalid
    }
  };

  // no-op if already initialized
  let _ = console_log::init_with_level(log_level);
}
