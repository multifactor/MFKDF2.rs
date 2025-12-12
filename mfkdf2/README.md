# MFKDF2

Multi-Factor Key Derivation Function (MFKDF) extends traditional password-based key derivation
by incorporating all of a user’s authentication factors, not just a single secret into the
derivation process. This crate enables constructing high-entropy cryptographic keys from
combinations of passwords, HOTP/TOTP codes, and hardware-backed authenticators such as `YubiKeys`.

Key capabilities include:
- **Multi-source entropy**: Derive key material from multiple independent factors (passwords,
  OTPs, hardware tokens), significantly raising the effective entropy and resistance to offline
  brute-force attacks.
- **Factor conjunction**: All required factors must be simultaneously correct to reproduce the
  key, creating an exponentially stronger search space than any single factor alone.
- **Threshold recovery**: Optional threshold schemes allow users to recover lost factors without
  relying on a central authority, avoiding single points of failure while preserving security
  guarantees.
- **Policy-driven authentication**: Keys can encode arbitrarily flexible authentication
  policies, enabling cryptographically enforced multi-factor requirements tailored to the
  application’s threat model.

# Factors

A Factor represents an authentication primitive. Each factor has:
- **Factor material**: the secret input (e.g., a password, TOTP secret, hardware key seed)
- **Public state**: non-secret metadata the factor needs to operate (e.g., counters,
  identifiers)

Examples:
- Password factor stores the password as its material and may use a static ID as its public
  state.
- TOTP/HOTP factor stores the shared secret as its material and uses public state such as the
  current counter.

# Supported factors
- Constant entropy factors:
  - [`UUID`](`crate::setup::factors::uuid::UUIDFactor`)
  - [`Password`](`crate::setup::factors::password::Password`)
  - [`Question`](`crate::setup::factors::question::Question`)
- Software Tokens:
  - [`HOTP`](`crate::setup::factors::hotp::HOTP`)
  - [`TOTP`](`crate::setup::factors::totp::TOTP`)
- Hardware Tokens:
  - [`HMACSHA1`](`crate::setup::factors::hmacsha1::HmacSha1`)
- Out-of-band Authentication:
  - [`OOBA`](`crate::setup::factors::ooba::Ooba`)
- `WebAuthn` factors:
  - [`Passkey`](`crate::setup::factors::passkey::Passkey`)

Additionally, [`Stack`](`crate::setup::factors::stack::Stack`) and
[`Persisted`](`crate::derive::factors::persisted::Persisted`) factors can be used to modify how a
key is derived.

# Factor Construction

A factor's construction defines how the factor is initialized and how it produces key material
over time. It consists of two algorithms:

## Setup
Initializes the factor with a secret and produces a public state with initial key material.

```rust
use mfkdf2::prelude::*;
# let TOTP_SECRET = vec![0u8; 20];
#
// setup a password factor with id "pwd"
let password_factor = setup_password("password", PasswordOptions { id: Some("pwd".to_string()) })?;

// setup a TOTP factor with id "totp"
let totp_factor = setup_totp(TOTPOptions {
  id: Some("totp".to_string()),
  secret: Some(TOTP_SECRET),
  ..Default::default()
})?;
# MFKDF2Result::Ok(())
```

## Derive
Takes the factor's witness and produces key material from the factor and the updated
  state.

```rust
# use mfkdf2::derive::factors::{password, totp};
# use mfkdf2::error::MFKDF2Error;
# use mfkdf2::error::MFKDF2Result;
#
// derive the password factor
let password_factor = password("password")?;

// derive the TOTP factor with code `123456`
let totp_factor = totp(123456, None)?;
# MFKDF2Result::Ok(())
```

# KDF construction

The MFKDF derivation combines all factor outputs into a single deterministic static key using
`MFKDFSetup` and `MFKDFDerive` algorithms.

## Setup Key

Before you can derive a multi-factor derived key, you must setup a "key policy," which specifies
how a key is derived and ensures the key is the same every time (as long as the factors are
correct).

```rust
use mfkdf2::prelude::*;
# let HOTP_SECRET = vec![0u8; 20];
#
// perform setup key
let setup_derived_key = setup::key(
  &[
    setup_password("password123", PasswordOptions::default()).expect("Failed to setup password factor"),
    setup_hmacsha1(HmacSha1Options::default())?,
    setup_hotp(HOTPOptions { secret: Some(HOTP_SECRET), ..Default::default() })?,
    // add more factors here
  ],
  MFKDF2Options::default(),
)?;
# MFKDF2Result::Ok(())
```

## Derive Key

After you have setup a key policy, you can derive the key from the policy and the factors.

1. $\kappa_i \leftarrow \text{Derive}(F_i, \text{witness}_i, \beta_i)$: Per-factor key material
2. $\sigma \leftarrow \text{Combine}(\kappa_1, \kappa_2, \dots, \kappa_n)$: Combine per-factor key material into a single key material
3. $K \leftarrow \text{KDF}(\sigma)$: Final static derived key
4. $\beta_i \leftarrow \text{Update}($F_i, K, \beta_i)$: Optional state update (counters, hardening)

```text
[F_hmacsha1] --HMAC--> (k_hmacsha1) \
[F_hotp]     --HOTP--> (k_hotp)      ---+--> [MFKDF] --> (K)
[F_pw]       --PW----> (k_pw)       /                   --> (State B)
```

## Examples

### Password + HOTP + HMACSHA1

Derive a composite key with password, hmacsha1 and hotp factors. Derive returns the
[`MFKDF2DerivedKey`](`crate::definitions::MFKDF2DerivedKey`) and updated [`Policy`](`crate::policy::Policy`).

```rust
# use std::collections::HashMap;
use mfkdf2::prelude::*;
# use hmac::{Mac, Hmac};
# use sha1::Sha1;
# let HOTP_SECRET = vec![0u8; 20];
# let HMACSHA1_SECRET = vec![0u8; 20];
#
let setup_password_factor = setup_password("password123", PasswordOptions::default())?;
let setup_hmac_factor = setup_hmacsha1(HmacSha1Options {
  secret: Some(HMACSHA1_SECRET.clone()),
  ..Default::default()
})?;
let setup_hotp_factor =
  setup_hotp(HOTPOptions { secret: Some(HOTP_SECRET.clone()), ..Default::default() })?;

// perform setup key
let setup_derived_key = setup::key(
  &[setup_password_factor, setup_hmac_factor, setup_hotp_factor],
  MFKDF2Options::default(),
)?;

// Derivation phase
let derive_password_factor = derive_password("password123")?;

# let policy_hmac_factor = setup_derived_key
#   .policy
#   .factors
#   .iter()
#   .find(|f| f.id == "hmacsha1").unwrap();
# let challenge = match &policy_hmac_factor.params {
#   FactorParams::HmacSha1(p) => hex::decode(&p.challenge).unwrap(),
#   _ => unreachable!(),
# };
# let response: [u8; 20] = <Hmac<Sha1> as Mac>::new_from_slice(&HMACSHA1_SECRET)
#    .unwrap()
#    .chain_update(challenge)
#    .finalize()
#    .into_bytes()
#    .into();
let derive_hmac_factor = derive_hmacsha1(response)?;
#
# let policy_hotp_factor = setup_derived_key
#   .policy
#   .factors
#   .iter()
#   .find(|f| f.id == "hotp").unwrap();
# let (counter, digits, hash) = match &policy_hotp_factor.params {
#   FactorParams::HOTP(p) => (p.counter, p.digits, p.hash.clone()),
#   _ => unreachable!(),
# };
# let correct_code = generate_otp_token(&HOTP_SECRET, counter, &hash, digits);
let derive_hotp_factor = derive_hotp(correct_code as u32)?;

let derived_key = derive::key(
  &setup_derived_key.policy,
  HashMap::from([
    (String::from("password"), derive_password_factor),
    (String::from("hmacsha1"), derive_hmac_factor),
    (String::from("hotp"), derive_hotp_factor),
  ]),
  true,
  false,
)?;

// derived_key.key -> 34d2…5771
# assert_eq!(derived_key.key, setup_derived_key.key);
# MFKDF2Result::Ok(())
```

### Password + TOTP

```rust
# use std::collections::HashMap;
use mfkdf2::prelude::*;

let setup = setup::key(
  &[
    setup_password("password1", PasswordOptions::default())?,
    setup_totp(TOTPOptions {
      secret: Some(b"abcdefghijklmnopqrst".to_vec()),
      time: Some(1),
      ..Default::default()
    })?,
  ],
  MFKDF2Options::default(),
)?;

let derived_key = derive::key(
  &setup.policy,
  HashMap::from([
    ("password".to_string(), derive_password("password1")?),
    (
      "totp".to_string(),
      derive_totp(
        241063,
        Some(TOTPDeriveOptions {
          time: Some(30001),
          ..Default::default()
        }),
      )?,
    ),
  ]),
  true,
  false,
)?;

println!("Derived Key: {:?}", derived_key);

# assert_eq!(setup.key, derived_key.key);
# MFKDF2Result::Ok(())
```

# Threshold Recovery

Threshold recovery generalizes a multi‑factor policy from “all factors required” to a
configurable `t`‑of‑`n` requirement. During setup, the derived secret is split into shares using
a Shamir‑style secret sharing scheme, one share per factor. During derive, any subset of factors
that supplies at least `threshold` valid shares can reconstruct the same secret and therefore
the same derived key.

**Note**: MFKDF2 provides no mechanism to invalidate old policies. When threshold is increased via [reconstitution](`crate::definitions::mfkdf_derived_key::reconstitution`), old policies can still be used to derive keys.

## Setup: configuring a 2‑of‑3 recovery policy

The snippet below constructs a 2‑of‑3 key from a password, an HOTP soft token, and a UUID
recovery code. Any 2 of these 3 factors are sufficient to reproduce the key.

```rust
# use std::collections::HashMap;
# use mfkdf2::error::MFKDF2Error;
# use mfkdf2::{setup, derive};
# use mfkdf2::setup::factors::{password::PasswordOptions, hotp::HOTPOptions};
# use mfkdf2::setup::factors::{uuid::UUIDOptions};
# use mfkdf2::derive::factors::hotp as derive_hotp;
# use mfkdf2::derive::factors::uuid as derive_uuid;
# use mfkdf2::otpauth::{generate_otp_token, HashAlgorithm};
# use mfkdf2::definitions::MFKDF2Options;
# use mfkdf2::setup::factors::uuid::Uuid;
#
// setup phase: construct factors
let password_factor = setup::factors::password("password123", PasswordOptions::default())?;

// HOTP uses a random secret and 6‑digit codes by default
let setup_hotp_factor = setup::factors::hotp(HOTPOptions::default())?;
let hotp_state = match &setup_hotp_factor.factor_type {
  mfkdf2::definitions::FactorType::HOTP(h) => h.clone(),
  _ => unreachable!("HOTPOptions always produce an HOTP factor"),
};

// UUID factor uses a stable UUID as a recovery code
let setup_uuid_factor =
  setup::factors::uuid(UUIDOptions { uuid: Some(Uuid::nil()), ..UUIDOptions::default() })?;

// configure a 2‑of‑3 threshold policy
let options = MFKDF2Options { threshold: Some(2), ..MFKDF2Options::default() };
let setup_derived = setup::key(&[password_factor, setup_hotp_factor, setup_uuid_factor], options)?;

// derive phase: build inputs for any 2 factors
let policy_hotp_factor: &mfkdf2::policy::PolicyFactor = setup_derived
  .policy
  .factors
  .iter()
  .find(|f| f.id == "hotp")
  .expect("policy must contain an HOTP factor");

// get hotp params
let hotp_params = match &policy_hotp_factor.params {
  mfkdf2::definitions::factor::FactorParams::HOTP(p) => p,
  _ => unreachable!("HOTP factor always gives HOTP params"),
};

let hotp_secret = &hotp_state.secret[..20];
let correct_code = generate_otp_token(hotp_secret, hotp_params.counter, &hotp_params.hash, hotp_params.digits);

let mut derive_factors = HashMap::new();

// HOTP factor provided by the current OTP displayed in the authenticator app
let mut derive_hotp_factor = derive_hotp(correct_code as u32)?;
derive_hotp_factor.id = Some("hotp".to_string());
derive_factors.insert("hotp".to_string(), derive_hotp_factor);

// UUID factor provided by the user's stored recovery code
let mut derive_uuid_factor = derive_uuid(Uuid::nil())?;
derive_uuid_factor.id = Some("uuid".to_string());
derive_factors.insert("uuid".to_string(), derive_uuid_factor);

// only 2 out of the 3 factors are provided here
let derived = derive::key(&setup_derived.policy, derive_factors, true, false)?;
assert_eq!(derived.key, setup_derived.key);
# Ok::<(), mfkdf2::error::MFKDF2Error>(())
```

Threshold value must be between 1 and the number of factors, otherwise
[`MFKDF2Error::InvalidThreshold`](`crate::error::MFKDF2Error::InvalidThreshold`) is returned.

```rust
# use mfkdf2::error::{MFKDF2Error, MFKDF2Result};
# use mfkdf2::setup::factors::{password, password::PasswordOptions};
# use mfkdf2::setup;
# use mfkdf2::definitions::MFKDF2Options;
#
// requesting 2‑of‑1 factors causes MFKDF2Error::InvalidThreshold
let result =
  setup::key(&[password("password123", PasswordOptions::default())?], MFKDF2Options { threshold: Some(2), ..MFKDF2Options::default() });
assert!(matches!(result, Err(MFKDF2Error::InvalidThreshold)));
# Ok::<(), mfkdf2::error::MFKDF2Error>(())
```

If insufficient factors are provided, share recovery fails and
[`MFKDF2Error::ShareRecovery`](`crate::error::MFKDF2Error::ShareRecovery`) is returned.

```rust
# use std::collections::HashMap;
#
# use mfkdf2::error::{MFKDF2Error, MFKDF2Result};
# use mfkdf2::setup::factors::{password as setup_password, password::PasswordOptions};
# use mfkdf2::setup;
# use mfkdf2::definitions::MFKDF2Options;
# use mfkdf2::derive::factors::password as derive_password;
# use mfkdf2::derive;
#
// setup phase with a 2‑of‑2 password policy
let setup_factors = &[
  setup_password("primary‑password", PasswordOptions { id: Some("pw1".into()) })?,
  setup_password("backup‑password", PasswordOptions { id: Some("pw2".into()) })?,
];
let options = MFKDF2Options { threshold: Some(2), ..MFKDF2Options::default() };
let setup_derived = setup::key(setup_factors, options)?;

// derive phase provides only one out of the two required factors
let mut derive_factors = HashMap::new();
let mut derive_pw1 = derive_password("primary‑password")?;
derive_pw1.id = Some("pw1".into());
derive_factors.insert("pw1".into(), derive_pw1);

let result = derive::key(&setup_derived.policy, derive_factors, true, false);
assert!(matches!(result, Err(MFKDF2Error::ShareRecovery)));
# Ok::<(), mfkdf2::error::MFKDF2Error>(())
```

These examples illustrate how a `t`‑of‑`n` MFKDF2 policy can express flexible recovery flows
(such as 2‑of‑3 password + HOTP + UUID or 3‑of‑5 enterprise policies) while preserving
cryptographic guarantees about the minimum factor set required to unlock a key.

# Key Stacking

Key stacking treats a derived key from one MFKDF2 policy as a reusable factor in another policy.
A stack factor wraps a complete inner policy and derived key, enabling nested constructions such
as `(password₁ ∧ password₂) ∨ password₃` or more elaborate hierarchies.

Direct use of [`Stack`](`crate::setup::factors::stack::stack`) Factor mainly serves advanced use cases; most
applications prefer configuring policies through higher‑level factor combinations and
thresholds.

## Example: `(password₁ ∧ password₂) ∨ password₃`

The following example configures a 2‑of‑2 inner stack over two passwords and an outer 1‑of‑2
policy between the stack and a third password:

```rust
# use std::collections::HashMap;
#
# use mfkdf2::error::MFKDF2Error;
# use mfkdf2::setup::factors::{password as setup_password, password::PasswordOptions};
# use mfkdf2::setup::factors::{stack as setup_stack, stack::StackOptions};
# use mfkdf2::setup;
# use mfkdf2::derive::factors::password as derive_password;
# use mfkdf2::derive::factors::stack as derive_stack;
# use mfkdf2::derive;
# use mfkdf2::definitions::MFKDF2Options;
#
// inner stack: password₁ ∧ password₂
let inner = vec![
  setup_password("password1", PasswordOptions { id: Some("password1".into()) })?,
  setup_password("password2", PasswordOptions { id: Some("password2".into()) })?,
];

let stacked = setup_stack(inner, StackOptions {
  id:        Some("stack".into()),
  threshold: Some(2),
  salt:      None,
})?;

// outer policy: (password₁ ∧ password₂) ∨ password₃
let password3 = setup_password("password3", PasswordOptions { id: Some("password3".into()) })?;

let setup_derived = setup::key(&[stacked, password3], MFKDF2Options {
  threshold: Some(1),
  ..MFKDF2Options::default()
})?;

// derive with password₁ and password₂ through a stack factor
let derive_stack_factor = derive_stack(HashMap::from([
  ("password1".to_string(), derive_password("password1")?),
  ("password2".to_string(), derive_password("password2")?),
]))?;

let derived = derive::key(
  &setup_derived.policy,
  HashMap::from([("stack".to_string(), derive_stack_factor)]),
  false,
  false,
)?;

# assert_eq!(derived.key, setup_derived.key);
# Ok::<(), mfkdf2::error::MFKDF2Error>(())
```

The same outer key can also be derived with only `password3` by supplying a single password
factor keyed by `"password3"` to [setup key](`crate::derive::key`).

# Integrity Protetion


MFKDF2 allows policy integrity to be enforced between each subsequent derives, and is enabled by default. An honest client will only accept a state if the key it derives from that state correctly validates the state’s integrity. Before deriving the final key, current policy's self-referential tag is checked. This is enabled using `verify` flag in [setup](`crate::setup::key`) and [derive](`crate::derive::key`). If any mismatch is detected, the [`PolicyIntegrityCheckFailed`](`crate::error::MFKDF2Error::PolicyIntegrityCheckFailed`) error is returned.

When integrity is disabled, adversary can modify factor public state like threshold, factor parameters, encrypted shares. This may expose underlying keys and factor secrets, reducing the overall entropy of the key.

# Feature Flags

- `bindings`: Generate FFI bindings of the library to other languages.
- `differential-test`: Enable changes required for deterministic testing.

# Differential Testing

Differential testing is used to ensure the correctness of the library. It is enabled by the
`differential-test` feature flag. It is performed by comparing the output of the library with
the output of the reference implementation.

The reference implementation is the JavaScript implementation of the MFKDF2 spec. It is available at
[MFKDF](https://github.com/multifactor/mfkdf).


