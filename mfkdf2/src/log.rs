use std::str::FromStr;

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
pub async fn init_log(level: Option<LogLevel>) {
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
