//! # MFKDF2
//! Multi-Factor Key Derivation Function (MFKDF) extends traditional password-based key derivation
//! by incorporating all of a user’s authentication factors, not just a single secret into the
//! derivation process. This crate enables constructing high-entropy cryptographic keys from
//! combinations of passwords, HOTP/TOTP codes, and hardware-backed authenticators such as YubiKeys.
//!
//! Key capabilities include:
//! - **Multi-source entropy**: Derive key material from multiple independent factors (passwords,
//!   OTPs, hardware tokens), significantly raising the effective entropy and resistance to offline
//!   brute-force attacks.
//! - **Factor conjunction**: All required factors must be simultaneously correct to reproduce the
//!   key, creating an exponentially stronger search space than any single factor alone.
//! - **Threshold recovery**: Optional threshold schemes allow users to recover lost factors without
//!   relying on a central authority, avoiding single points of failure while preserving security
//!   guarantees.
//! - **Policy-driven authentication**: Keys can encode arbitrarily flexible authentication
//!   policies, enabling cryptographically enforced multi-factor requirements tailored to the
//!   application’s threat model.
//!
//! # Factors
//!
//! A Factor represents an authentication primitive. Each factor has:
//! - **Factor material**: the secret input (e.g., a password, TOTP secret, hardware key seed)
//! - **Public state**: non-secret metadata the factor needs to operate (e.g., counters,
//!   identifiers)
//!
//! Examples:
//! - Password factor stores the password as its material and may use a static ID as its public
//!   state.
//! - TOTP/HOTP factor stores the shared secret as its material and uses public state such as the
//!   current counter.
//!
//! # Supported factors
//! - Constant entropy factors:
//!   - [UUID](`crate::setup::factors::uuid::UUIDFactor`)
//!   - [Password](`crate::setup::factors::password::Password`)
//!   - [Question](`crate::setup::factors::question::Question`)
//! - Software Tokens:
//!   - [HOTP](`crate::setup::factors::hotp::HOTP`)
//!   - [TOTP](`crate::setup::factors::totp::TOTP`)
//! - Hardware Tokens:
//!   - [HMACSHA1](`crate::setup::factors::hmacsha1::HmacSha1`)
//! - Out-of-band Authentication:
//!   - [OOBA](`crate::setup::factors::ooba::Ooba`)
//! - WebAuthn factors:
//!   - [Passkey](`crate::setup::factors::passkey::Passkey`)
//!
//! Additionally, [Stack](`crate::setup::factors::stack::Stack`) and
//! [Persisted](`crate::derive::factors::persisted::Persisted`) factors can be used to modify how a
//! key is derived.
//!
//! # Factor Construction
//!
//! A factor's construction defines how the factor is initialized and how it produces key material
//! over time. It consists of two algorithms:
//!
//! ## Setup
//! Initializes the factor with a secret and produces a public state with initial key material.
//!
//! ```rust
//! # use mfkdf2::setup::factors::password::{password, PasswordOptions};
//! # use mfkdf2::setup::factors::totp::{totp, TOTPOptions};
//! # let TOTP_SECRET = vec![0u8; 20];
//!
//! // setup a password factor with id "pwd"
//! let password_factor = password("password", PasswordOptions { id: Some("pwd".to_string()) })
//!   .expect("Failed to setup password factor");
//!
//! // setup a TOTP factor with id "totp"
//! let totp_factor = totp(TOTPOptions {
//!   id: Some("totp".to_string()),
//!   secret: Some(TOTP_SECRET),
//!   ..Default::default()
//! })
//! .expect("Failed to setup TOTP factor");
//! ```
//!
//! ## Derive
//! Takes the factor's witness and produces key material from the factor and the updated
//!   state.
//!
//! ```rust
//! # use mfkdf2::derive::factors::{password, totp};
//!
//! // derive the password factor
//! let password_factor = password("password").expect("Failed to derive password factor");
//!
//! // derive the TOTP factor with code `123456`
//! let totp_factor = totp(123456, None).expect("Failed to derive TOTP factor");
//! ```
//!
//! # KDF construction
//!
//! The MFKDF derivation combines all factor outputs into a single deterministic static key using
//! MFKDFSetup and MFKDFDerive algorithms.
//!
//! ## Setup Key
//!
//! Before you can derive a multi-factor derived key, you must setup a "key policy," which specifies
//! how a key is derived and ensures the key is the same every time (as long as the factors are
//! correct).
//!
//! ```rust
//! # use mfkdf2::setup::factors::password::{password, PasswordOptions};
//! # use mfkdf2::setup::factors::hmacsha1::{hmacsha1, HmacSha1Options};
//! # use mfkdf2::setup::factors::hotp::{hotp, HOTPOptions};
//! # use mfkdf2::setup::key::{key as setup_key, MFKDF2Options};
//! # let HOTP_SECRET = vec![0u8; 20];
//!
//! let setup_hmac_factor =
//!   hmacsha1(HmacSha1Options::default()).expect("Failed to setup HMACSHA1 factor");
//!
//! // perform setup key
//! let setup_derived_key = setup_key(
//!   &[
//!     password("password123", PasswordOptions::default()).expect("Failed to setup password factor"),
//!     hmacsha1(HmacSha1Options::default()).expect("Failed to setup HMACSHA1 factor"),
//!     hotp(HOTPOptions { secret: Some(HOTP_SECRET), ..Default::default() })
//!       .expect("Failed to setup HOTP factor"),
//!     // add more factors here
//!   ],
//!   MFKDF2Options::default(),
//! )
//! .expect("Failed to setup derived key");
//! ```
//!
//! # Derive Key
//!
//! After you have setup a key policy, you can derive the key from the policy and the factors.
//!
//! 1. κᵢ ←  Derive(Fᵢ, witnessᵢ, βᵢ): Per-factor key material
//! 2. σ  ←  Combine(κ₁, κ₂, …, κₙ): Combine per-factor key material into a single key material
//! 3. K  ←  KDF(σ): Final static derived key
//! 4. βᵢ ←  Update(Fᵢ, K, βᵢ): Optional state update (counters, hardening)
//!
//! ```text
//! [F_hmacsha1] --HMAC--> (k_hmacsha1) \
//! [F_hotp]     --HOTP--> (k_hotp)      ---+--> [MFKDF] --> (K)
//! [F_pw]       --PW----> (k_pw)       /                   --> (State B)
//! ```
//!
//! ## Examples
//!
//! Derive a composite key with password, hmacsha1 and hotp factors. Derive returns the
//! [`crate::definitions::MFKDF2DerivedKey`] and updated [`crate::policy::Policy`].
//!
//! ```rust
//! # use std::collections::HashMap;
//! # use mfkdf2::setup::factors::password::{password as setup_password, PasswordOptions};
//! # use mfkdf2::setup::factors::hmacsha1::{hmacsha1 as setup_hmacsha1, HmacSha1Options};
//! # use mfkdf2::setup::factors::hotp::{hotp as setup_hotp, HOTPOptions};
//! # use mfkdf2::setup::key::{key as setup_key, MFKDF2Options};
//! # use mfkdf2::derive::factors::password::password as derive_password;
//! # use mfkdf2::derive::factors::hmacsha1::hmacsha1 as derive_hmacsha1;
//! # use mfkdf2::derive::factors::hotp::hotp as derive_hotp;
//! # use mfkdf2::otpauth::generate_hotp_code;
//! # use mfkdf2::derive::key::key as derive_key;
//! # let HOTP_SECRET = vec![0u8; 20];
//! # let HMACSHA1_SECRET = vec![0u8; 20];
//!
//! let setup_password_factor = setup_password("password123", PasswordOptions::default()).unwrap();
//! let setup_hmac_factor =
//!   setup_hmacsha1(HmacSha1Options { secret: Some(HMACSHA1_SECRET.clone()), ..Default::default() }).expect("Failed to setup HMACSHA1 factor");
//! let setup_hotp_factor = setup_hotp(HOTPOptions { secret: Some(HOTP_SECRET.clone()), ..Default::default() })
//!   .expect("Failed to setup HOTP factor");
//!
//! // perform setup key
//! let setup_derived_key =
//!   setup_key(&[setup_password_factor, setup_hmac_factor, setup_hotp_factor], MFKDF2Options::default())
//!     .expect("Failed to setup derived key");
//!
//! // Derivation phase
//! let derive_password_factor =
//!   derive_password("password123").expect("Failed to derive password factor");
//!
//! # let policy_hmac_factor = setup_derived_key
//! #   .policy
//! #   .factors
//! #   .iter()
//! #   .find(|f| f.id == "hmacsha1")
//! #   .expect("Failed to find HMACSHA1 factor");
//! # let challenge =
//! #   hex::decode(&policy_hmac_factor.params["challenge"].as_str().expect("Failed to get challenge"))
//! #    .expect("Failed to decode challenge");
//! # let response = mfkdf2::crypto::hmacsha1(&HMACSHA1_SECRET, &challenge);
//! let derive_hmac_factor =
//!   derive_hmacsha1(response.into()).expect("Failed to derive HMACSHA1 factor");
//!
//! # let policy_hotp_factor = setup_derived_key
//! #   .policy
//! #   .factors
//! #   .iter()
//! #   .find(|f| f.id == "hotp")
//! #   .expect("Failed to find HOTP factor");
//! # let counter = policy_hotp_factor.params["counter"].as_u64().expect("Failed to get counter");
//! # let hash = serde_json::from_value(policy_hotp_factor.params["hash"].clone()).expect("Failed to get hash");
//! # let digits = policy_hotp_factor.params["digits"].as_u64().expect("Failed to get digits") as u32;
//! # let correct_code = generate_hotp_code(&HOTP_SECRET, counter, &hash, digits);
//! let derive_hotp_factor = derive_hotp(correct_code as u32).expect("Failed to derive HOTP factor");
//!
//! let derived_key = derive_key(
//!   &setup_derived_key.policy,
//!   HashMap::from([
//!     (String::from("password"), derive_password_factor),
//!     (String::from("hmacsha1"), derive_hmac_factor),
//!     (String::from("hotp"), derive_hotp_factor),
//!   ]),
//!   false,
//!   false,
//! )
//! .expect("Failed to derive key");
//!
//! // derived_key.key -> 34d2…5771
//! # assert_eq!(derived_key.key, setup_derived_key.key);
//! ```
//!
//! # Feature Flags
//!
//! - `bindings`: Generate FFI bindings of the library to other languages.
//! - `differential-test`: Enable changes required for deterministic testing.
//!
//! # Differential Testing
//!
//! Differential testing is used to ensure the correctness of the library. It is enabled by the
//! `differential-test` feature flag. It is performed by comparing the output of the library with
//! the output of the reference implementation.
//!
//! The reference implementation is the JavaScript implementation of the MFKDF2 spec. It is available at [MFKDF](https://github.com/multifactor/mfkdf).
pub mod constants;
mod crypto;
pub mod definitions;
pub mod derive;
pub mod error;
pub mod integrity;
mod log;
pub mod otpauth;
pub mod policy;
mod rng;
pub mod setup;

#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();
