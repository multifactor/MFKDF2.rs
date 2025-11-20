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
//! # use mfkdf2::error::MFKDF2Error;
//! # let TOTP_SECRET = vec![0u8; 20];
//!
//! // setup a password factor with id "pwd"
//! let password_factor = password("password", PasswordOptions { id: Some("pwd".to_string()) })?;
//!
//! // setup a TOTP factor with id "totp"
//! let totp_factor = totp(TOTPOptions {
//!   id: Some("totp".to_string()),
//!   secret: Some(TOTP_SECRET),
//!   ..Default::default()
//! })?;
//! # Ok::<(), mfkdf2::error::MFKDF2Error>(())
//! ```
//!
//! ## Derive
//! Takes the factor's witness and produces key material from the factor and the updated
//!   state.
//!
//! ```rust
//! # use mfkdf2::derive::factors::{password, totp};
//! # use mfkdf2::error::MFKDF2Error;
//!
//! // derive the password factor
//! let password_factor = password("password")?;
//!
//! // derive the TOTP factor with code `123456`
//! let totp_factor = totp(123456, None)?;
//! # Ok::<(), mfkdf2::error::MFKDF2Error>(())
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
//! # use mfkdf2::error::MFKDF2Error;
//! # let HOTP_SECRET = vec![0u8; 20];
//!
//! let setup_hmac_factor = hmacsha1(HmacSha1Options::default())?;
//!
//! // perform setup key
//! let setup_derived_key = setup_key(
//!   &[
//!     password("password123", PasswordOptions::default()).expect("Failed to setup password factor"),
//!     hmacsha1(HmacSha1Options::default())?,
//!     hotp(HOTPOptions { secret: Some(HOTP_SECRET), ..Default::default() })?,
//!     // add more factors here
//!   ],
//!   MFKDF2Options::default(),
//! )?;
//! # Ok::<(), mfkdf2::error::MFKDF2Error>(())
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
//! # use mfkdf2::error::MFKDF2Error;
//! # let HOTP_SECRET = vec![0u8; 20];
//! # let HMACSHA1_SECRET = vec![0u8; 20];
//!
//! let setup_password_factor = setup_password("password123", PasswordOptions::default())?;
//! let setup_hmac_factor = setup_hmacsha1(HmacSha1Options {
//!   secret: Some(HMACSHA1_SECRET.clone()),
//!   ..Default::default()
//! })?;
//! let setup_hotp_factor =
//!   setup_hotp(HOTPOptions { secret: Some(HOTP_SECRET.clone()), ..Default::default() })?;
//!
//! // perform setup key
//! let setup_derived_key = setup_key(
//!   &[setup_password_factor, setup_hmac_factor, setup_hotp_factor],
//!   MFKDF2Options::default(),
//! )?;
//!
//! // Derivation phase
//! let derive_password_factor = derive_password("password123")?;
//!
//! # let policy_hmac_factor = setup_derived_key
//! #   .policy
//! #   .factors
//! #   .iter()
//! #   .find(|f| f.id == "hmacsha1")?;
//! # let challenge =
//! #   hex::decode(&policy_hmac_factor.params["challenge"].as_str()?)?;
//! # let response = mfkdf2::crypto::hmacsha1(&HMACSHA1_SECRET, &challenge);
//! let derive_hmac_factor = derive_hmacsha1(response.into())?;
//!
//! # let policy_hotp_factor = setup_derived_key
//! #   .policy
//! #   .factors
//! #   .iter()
//! #   .find(|f| f.id == "hotp")?;
//! # let counter = policy_hotp_factor.params["counter"].as_u64()?;
//! # let hash = serde_json::from_value(policy_hotp_factor.params["hash"].clone())?;
//! # let digits = policy_hotp_factor.params["digits"].as_u64()? as u32;
//! # let correct_code = generate_hotp_code(&HOTP_SECRET, counter, &hash, digits);
//! let derive_hotp_factor = derive_hotp(correct_code as u32)?;
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
//! )?;
//!
//! // derived_key.key -> 34d2…5771
//! # assert_eq!(derived_key.key, setup_derived_key.key);
//! # Ok::<(), mfkdf2::error::MFKDF2Error>(())
//! ```
//!
//! # Threshold Recovery
//!
//! Threshold recovery generalizes a multi‑factor policy from “all factors required” to a
//! configurable `t`‑of‑`n` requirement. During setup, the derived secret is split into shares using
//! a Shamir‑style secret sharing scheme, one share per factor. During derive, any subset of factors
//! that supplies at least `threshold` valid shares can reconstruct the same secret and therefore
//! the same derived key.
//!
//! ## Setup: configuring a 2‑of‑3 recovery policy
//!
//! The snippet below constructs a 2‑of‑3 key from a password, an HOTP soft token, and a UUID
//! recovery code. Any 2 of these 3 factors are sufficient to reproduce the key.
//!
//! ```rust
//! # use std::collections::HashMap;
//! #
//! # use mfkdf2::error::MFKDF2Error;
//! # use mfkdf2::setup::factors::password::{password as setup_password, PasswordOptions};
//! # use mfkdf2::setup::factors::hotp::{hotp as setup_hotp, HOTPOptions};
//! # use mfkdf2::setup::factors::uuid::{uuid as setup_uuid, UUIDOptions};
//! # use mfkdf2::setup::key::{key as setup_key, MFKDF2Options};
//! # use mfkdf2::derive::factors::hotp::hotp as derive_hotp;
//! # use mfkdf2::derive::factors::uuid::uuid as derive_uuid;
//! # use mfkdf2::derive::key::key as derive_key;
//! # use mfkdf2::otpauth::{generate_otp_token as generate_hotp_code, HashAlgorithm};
//! # use mfkdf2::setup::FactorSetup;
//! # use uuid::Uuid;
//! #
//! # fn main() -> Result<(), MFKDFError> { example_2_of_3()?; Ok(()) }
//! #
//! # fn example_2_of_3() -> Result<(), MFKDFError> {
//! // setup phase: construct factors
//! let password_factor = setup_password("password123", PasswordOptions::default())?;
//!
//! // HOTP uses a random secret and 6‑digit codes by default
//! let setup_hotp_factor = setup_hotp(HOTPOptions::default())?;
//! let hotp_state = match &setup_hotp_factor.factor_type {
//!   mfkdf2::definitions::FactorType::HOTP(h) => h,
//!   _ => unreachable!("HOTPOptions always produce an HOTP factor"),
//! };
//!
//! // UUID factor uses a stable UUID as a recovery code
//! let setup_uuid_factor =
//!   setup_uuid(UUIDOptions { uuid: Some(Uuid::nil()), ..UUIDOptions::default() })?;
//!
//! // configure a 2‑of‑3 threshold policy
//! let options = MFKDF2Options { threshold: Some(2), ..MFKDF2Options::default() };
//! let setup_derived = setup_key(&[password_factor, setup_hotp_factor, setup_uuid_factor], options)?;
//!
//! // derive phase: build inputs for any 2 factors
//! let policy_hotp_factor: &mfkdf2::policy::PolicyFactor = setup_derived
//!   .policy
//!   .factors
//!   .iter()
//!   .find(|f| f.id == "hotp")
//!   .expect("policy must contain an HOTP factor");
//!
//! let counter = policy_hotp_factor.params["counter"].as_u64().expect("counter must be present");
//! let hash: HashAlgorithm =
//!   serde_json::from_value(policy_hotp_factor.params["hash"].clone()).expect("hash must decode");
//! let digits = policy_hotp_factor.params["digits"].as_u64().expect("digits must be present") as u32;
//! let hotp_secret = &hotp_state.config.secret[..20];
//! let correct_code = generate_hotp_code(hotp_secret, counter, &hash, digits);
//!
//! let mut derive_factors = HashMap::new();
//!
//! // HOTP factor provided by the current OTP displayed in the authenticator app
//! let mut derive_hotp_factor = derive_hotp(correct_code as u32)?;
//! derive_hotp_factor.id = Some("hotp".to_string());
//! derive_factors.insert("hotp".to_string(), derive_hotp_factor);
//!
//! // UUID factor provided by the user's stored recovery code
//! let mut derive_uuid_factor = derive_uuid(Uuid::nil())?;
//! derive_uuid_factor.id = Some("uuid".to_string());
//! derive_factors.insert("uuid".to_string(), derive_uuid_factor);
//!
//! // only 2 out of the 3 factors are provided here
//! let derived = derive_key(&setup_derived.policy, derive_factors, true, false)?;
//! assert_eq!(derived.key, setup_derived.key);
//! # Ok(())
//! # }
//! ```
//!
//! Threshold value must be between 1 and the number of factors, otherwise
//! [`crate::error::MFKDF2Error::InvalidThreshold`] is returned.
//!
//! ```rust
//! # use mfkdf2::error::{MFKDF2Error, MFKDF2Result};
//! # use mfkdf2::setup::factors::password::{password, PasswordOptions};
//! # use mfkdf2::setup::key::{key as setup_key, MFKDF2Options};
//! #
//! # fn invalid_threshold_example() -> MFKDF2Result<()> {
//! let factor = password("password123", PasswordOptions::default())?;
//!
//! // requesting 2‑of‑1 factors causes MFKDF2Error::InvalidThreshold
//! let result =
//!   setup_key(&[factor], MFKDF2Options { threshold: Some(2), ..MFKDF2Options::default() });
//! assert!(matches!(result, Err(MFKDF2Error::InvalidThreshold)));
//! # Ok(())
//! # }
//! ```
//!
//! If insufficient factors are provided, share recovery fails and
//! [`crate::error::MFKDF2Error::ShareRecoveryError`] is returned.
//!
//! ```rust
//! # use std::collections::HashMap;
//! #
//! # use mfkdf2::error::{MFKDF2Error, MFKDF2Result};
//! # use mfkdf2::setup::factors::password::{password as setup_password, PasswordOptions};
//! # use mfkdf2::setup::key::{key as setup_key, MFKDF2Options};
//! # use mfkdf2::derive::factors::password::password as derive_password;
//! # use mfkdf2::derive::key::key as derive_key;
//! #
//! # fn insufficient_factors_example() -> MFKDF2Result<()> {
//! // setup phase with a 2‑of‑2 password policy
//! let setup_factors = &[
//!   setup_password("primary‑password", PasswordOptions { id: Some("pw1".into()) })?,
//!   setup_password("backup‑password", PasswordOptions { id: Some("pw2".into()) })?,
//! ];
//! let options = MFKDF2Options { threshold: Some(2), ..MFKDF2Options::default() };
//! let setup_derived = setup_key(setup_factors, options)?;
//!
//! // derive phase provides only one out of the two required factors
//! let mut derive_factors = HashMap::new();
//! let mut derive_pw1 = derive_password("primary‑password")?;
//! derive_pw1.id = Some("pw1".into());
//! derive_factors.insert("pw1".into(), derive_pw1);
//!
//! let result = derive_key(&setup_derived.policy, derive_factors, true, false);
//! assert!(matches!(result, Err(MFKDF2Error::ShareRecoveryError)));
//! # Ok(())
//! # }
//! ```
//!
//! These examples illustrate how a `t`‑of‑`n` MFKDF2 policy can express flexible recovery flows
//! (such as 2‑of‑3 password + HOTP + UUID or 3‑of‑5 enterprise policies) while preserving
//! cryptographic guarantees about the minimum factor set required to unlock a key.
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
