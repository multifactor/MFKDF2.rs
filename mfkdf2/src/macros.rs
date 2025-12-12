//! # Factor Macros
//!
//! This module provides declarative macros that reduce boilerplate in factor definitions while
//! maintaining compatibility with UniFFI bindings.
//!
//! ## Design Rationale
//!
//! UniFFI requires explicit enum definitions with `#[derive(uniffi::Enum)]` attributes that it can
//! scan at bindgen time. This means we cannot generate entire enum definitions via proc-macros.
//! Instead, we use declarative macros to eliminate the *dispatch* boilerplate while keeping type
//! definitions explicit.
//!
//! ## References
//!
//! This approach is inspired by patterns in:
//! - [`enum_dispatch`](https://docs.rs/enum_dispatch) crate (trait dispatch via enums)
//! - [`strum`](https://docs.rs/strum) crate (enum utilities)
//! - Serde's internal macro patterns for enum handling

/// Dispatches a method call on `FactorType` to its inner factor implementation,
/// wrapping the result in the corresponding `FactorParams` variant.
///
/// # Syntax
///
/// ```rust,ignore
/// factor_dispatch_params!($factor_type_expr, $method($($args),*), $key_expr => {
///     $Variant1 => $ParamsVariant1,
///     $Variant2 => $ParamsVariant2,
///     // ...
/// })
/// ```
///
/// # Example
///
/// ```rust,ignore
/// let params = factor_dispatch_params!(self.0, params(key), key => {
///     Password => Password,
///     HOTP => HOTP,
///     TOTP => TOTP,
///     // ...
/// })?;
/// ```
#[macro_export]
macro_rules! factor_dispatch_params {
    // Variant: with key argument for params() method
    ($factor:expr, params($key:expr) => {
        $($variant:ident => $params_variant:ident),+ $(,)?
    }) => {
        Ok(match $factor {
            $(
                $crate::definitions::FactorType::$variant(inner) =>
                    $crate::definitions::factor::FactorParams::$params_variant(inner.params($key)?),
            )+
        })
    };

    // Variant: with unreachable Persisted (for setup context)
    ($factor:expr, params($key:expr) => {
        $($variant:ident => $params_variant:ident),+ $(,)?
    }; unreachable_persisted) => {
        Ok(match $factor {
            $(
                $crate::definitions::FactorType::$variant(inner) =>
                    $crate::definitions::factor::FactorParams::$params_variant(inner.params($key)?),
            )+
            $crate::definitions::FactorType::Persisted(_) =>
                unreachable!("Persisted factor should not be used in setup context"),
        })
    };

    // Variant: without arguments (for other methods that return Self::Params)
    ($factor:expr, $method:ident() => {
        $($variant:ident => $params_variant:ident),+ $(,)?
    }) => {
        Ok(match $factor {
            $(
                $crate::definitions::FactorType::$variant(inner) =>
                    $crate::definitions::factor::FactorParams::$params_variant(inner.$method()?),
            )+
        })
    };
}

/// Dispatches a method call on `FactorType` to its inner factor implementation,
/// serializing the output to `serde_json::Value`.
///
/// # Example
///
/// ```rust,ignore
/// let output = factor_dispatch_output!(self.0, output() => {
///     Password, HOTP, TOTP, Question, UUID, HmacSha1, OOBA, Passkey, Stack, Persisted
/// });
/// ```
#[macro_export]
macro_rules! factor_dispatch_output {
    ($factor:expr, $method:ident() => {
        $($variant:ident),+ $(,)?
    }) => {
        match $factor {
            $(
                $crate::definitions::FactorType::$variant(inner) =>
                    serde_json::to_value(inner.$method()).unwrap(),
            )+
        }
    };

    // Variant: with unreachable Persisted (for setup context)
    ($factor:expr, $method:ident() => {
        $($variant:ident),+ $(,)?
    }; unreachable_persisted) => {
        match $factor {
            $(
                $crate::definitions::FactorType::$variant(inner) =>
                    serde_json::to_value(inner.$method()).unwrap(),
            )+
            $crate::definitions::FactorType::Persisted(_) =>
                unreachable!("Persisted factor should not be used in setup context"),
        }
    };
}

/// Dispatches a method call on `FactorType` returning the inner type's result.
///
/// Useful for methods like `kind()` and `bytes()` that don't need wrapping.
///
/// # Example
///
/// ```rust,ignore
/// factor_dispatch_method!(self, kind() => { Password, HOTP, TOTP, ... })
/// factor_dispatch_method!(self, bytes() => { Password, HOTP, TOTP, ... })
/// ```
#[macro_export]
macro_rules! factor_dispatch_method {
    ($factor:expr, $method:ident() => {
        $($variant:ident),+ $(,)?
    }) => {
        match $factor {
            $(Self::$variant(inner) => inner.$method(),)+
        }
    };
}

/// Dispatches `include_params` on `FactorType`, matching factor and params variants.
///
/// This macro handles the case where both `FactorType` and `FactorParams` must
/// have matching variants for the operation to succeed.
///
/// # Example
///
/// ```rust,ignore
/// factor_dispatch_include_params!(self, params => {
///     Password, HOTP, TOTP, Question, UUID, HmacSha1, OOBA, Passkey, Stack, Persisted
/// })
/// ```
#[macro_export]
macro_rules! factor_dispatch_include_params {
    ($factor:expr, $params:expr => {
        $($variant:ident),+ $(,)?
    }) => {
        match ($factor, $params) {
            $(
                (
                    $crate::definitions::FactorType::$variant(inner),
                    $crate::definitions::factor::FactorParams::$variant(p)
                ) => inner.include_params(p),
            )+
            (f, _) => Err($crate::error::MFKDF2Error::InvalidDeriveParams(format!(
                "factor type mismatch: expected {} params",
                f.kind()
            ))),
        }
    };
}

/// Implements the `Factor` trait for a factor type.
///
/// This macro standardizes the boilerplate for implementing `Factor`:
/// - `kind()` returns a static string identifying the factor type
/// - `bytes()` returns the factor's secret material as bytes
///
/// # Example
///
/// ```rust,ignore
/// impl_factor! {
///     Password {
///         kind: "password",
///         params: PasswordParams,
///         output: PasswordOutput,
///         bytes: |self| self.password.as_bytes().to_vec(),
///     }
/// }
/// ```
#[macro_export]
macro_rules! impl_factor {
    (
        $factor:ty {
            kind: $kind:literal,
            params: $params:ty,
            output: $output:ty,
            bytes: |$self:ident| $bytes_expr:expr $(,)?
        }
    ) => {
        impl $crate::traits::Factor for $factor {
            type Output = $output;
            type Params = $params;

            fn kind(&$self) -> &'static str {
                $kind
            }

            fn bytes(&$self) -> Vec<u8> {
                $bytes_expr
            }
        }
    };
}
