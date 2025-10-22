## TODO
- [ ] complete all factor setup and derive
- [ ] complete tests
  - setup
  - derive pass/fail
  - threshold setup/derive
  - factors
- [ ] differential test with mfkdf2.js reference implementation

# Notes
- What i have to do is generate bindings for javascript such that it can differentially test with mfkdf2.js reference implementation.

16-09
- starting with implementing all factors setups and derive. Found some deviation in the reference implementation with the paper. notified Colin about the changes, and took clarity for myself.
- Notable changes include:
  - Using derived key to generate mac integrity key, but in reference implementation secret is used. This created confusion regarding the usage of key and secret, and where/how both is used?
    - **Action**: Colin mentioned that only key $K$ is used to derive the mac key, and that it might be a typo in the paper.
  - Multiple keys are required to encrypt derived key, factor secret, shares, integrity. Although it's mentioned in the paper that all keys will be encrypted using safe PRP, but algorithm in appendix and implementation should mention how and why?
    - **Action**: This improves readability of the code, and prevents confusion from the paper.
  - It was particularly difficult for me to deduce how the key encapsulation was being done in factor setup `key` function, and so I had to do some back and forth between the paper. But the paper doesn't mention how encapsulation of derived key happens using master secret.
    - **Action**: More inline comments in the implementation makes it easier for a first time reader to understand the code.

17-09
- Questions:
  - what does param output accomplish, and why is it different in factors? For example: password factor returns secret strength as param output, but uuid simply returns the uuid, and hotp returns all public and private (secret) parameters.
    - Ans: Treat setup output as user-facing information, and factor params as information required to derive the key.
  - how to pass the entropy as param output for password and question? i.e. what can be added inside factor options and what need to be excluded?
    - recalculate entropy lazily inside the function instead of storing
  - is storing padded_secret inside the factor type correct, because otherwise random pad need to be added for each derive?
    - follow reference implementation
- Updates:
  - submitted binding PR
  - done with factor setup
  - tomorrow: split factorTrait into setup and derive traint and complete factor derivation
  - start finishing rust tests, and adding ts tests from reference implementation

18-09
- Use some good rust libraries as reference to make mfkdf2 beautiful
  - https://github.com/pola-rs/polars
  - https://github.com/casey/just
  - https://github.com/astral-sh/uv
  - https://github.com/tokio-rs/axum
  - hyper
  - other async rust ecosystem repos
- sections that can be added in the docs/readme
  - performance
  - getting help
  - examples
- TODO: uniffi only support some custom types. Implement custom types at a later point.
- BUG: reference implementation for ooba uses nodejs cryptokey as its type, it would be better to use the exportkey type since it's rfc compliant.
- all setup factors implemented. derive factors and tests remaining

19-09
- refactor: FactorTrait -> FactorSetupTrait
- struct: MFKDF2DerivedFactor
- Trait: FactorDeriveTrait(`fn kind, fn bytes, fn include_params, fn params_Derive, fn output_derive`)
- difference between derive and setup factor construction function is that derive factor now returns an async closure that takes factor params from the policy, and returns the factor information (param derive, output derive).
  - Understand how the params is used in different factors, and find out if `include_params` function is enough, or an async closure is needed at rust side as well?
  - Sol1: use `include_params` to add all the params to the factor struct, and then use in `params_Derive` function
  - Sol2: have factor construction function return a closure that gets executed inside key derive. Problem with this approach is it's similar to sol1 (anonymous closure instead of named). I still have to save the params somewhere for params derive.
- TODO: can we move each factor params to their own structs, instead of playing with json value?
- QUES: what are the params for question factor?
- Instead of returning a struct from factor construction functions, it would be better to return a future. Closer to what is done in javascript and much more easier to understand and reason than storing the params in the struct.
- TODO: create a factor metadata trait that gets extended by factorsetup and factor derive trait
- BUG: can't find any check for oracle's length in reference implementation
- TODO: `include_params` should be a function outside the factortrait, so that struct can remain unintialised even befre params call, otherwise it's a bug, if a call happens before params is included.
- Call with Colin today:
  - Plan for next week: complete all policy, reconstitution features, and complete differential testing with js. that means creating a npm package from bindings, test directly in reference js implementaion.
  - Plan for week after that: python, kotlin bindings, rust refactoring, property-based tests, docs, cleaner repo.
  - Buffer week after that.

22-09:
- add policy features, complete derive key step
- start adding unit tests from reference impl
- Call log:
  - The goal of the repo is to make the binding api for ts look same as reference, but the other language impl can be different, and should natural to the user of that language.
  - Make sure to split your work into atomic single-day PRs rather than a big one or two each week.

{23,24}-09:
- TODO: remove async funcs after binding is done and tested
- TODO: add inline functions

26-09:
- complete integration tests
- complete policy tests
- merge both PRs
- remove some todos

30-09:

## TS Bindings
- TS bindings are generated using uniffi by doing just `gen-ts-bindings`. Every factor is annotated with `uniffi::Record`, and function with `uniffi::export`
- Initial goal is to make each individual factor test for setup run properly in ts.
- Starting with password: `mfkdf2-web/test/setup/factors/password.test.ts`. This is the test that should run properly.
- Need to look at the generated bindings from rust: `mfkdf2-web/src/generated/web/`
- What changes do i need to make at ts api: `mfkdf2-web/src/api.ts` and rust api to make this factor work exactly the same as reference impl? Goal is to keep the facade minimal and use more validation/checks on the rust side.
- factors and traits are defined in `setup/factors/mod.rs`
- individual factor setup is done in `setup/factors/<factor_name>.rs`
- typescript MFKDFFactor looks like:
```
/**
 * @typedef MFKDFFactor
 * @type {object}
 * @property {string} type - Type of factor
 * @property {string} [id] - Unique identifier of this factor
 * @property {Buffer} data - Key material for this factor
 * @property {function} params - Asynchronous function to fetch parameters
 * @property {number} [entropy] - Actual bits of entropy this factor provides
 * @property {function} [output] - Asynchronous function to fetch output
 */
```

- Need to look at `FactorSetup` trait, and `setup/factors/password.rs` to look at the api

What needs to be done:
- [x] create a facade over rust's `MFKDKF2Factor` so that it looks like reference's `MFKDFFactor`
- [x] MFKDF2Error is not recognised as a javascript error, so you have to either wrap it around a new error type, or catch it explicitly.
- TODO: uniffi only allows object implementations that are send + sync to allow for multithreading support from foreign language. That means no function that takes mutable reference to the object.
  - You have to use interior mutability pattern to modify the object. Maybe using RwLock or Mutex.
- [x] TODO: Policy impls are also not able to get exported through uniffi
- BUG: Due to difference in struct's representation at js and rust side, most of the types have to wrapped in order to provide the constructors, and that messes up typescript because every type becomes `any`

03-10:
- threshold: k
- gf256sss(secret): each byte `b` in secret `s` (32 byte) -> gen random poly (f_i) of degree k with `a0 = b` -> generate at max 255 shares by evaluating polys `(x, [f_1(x), f_2(x)])` for all `x in 1..255`
- recover(shares): 

06-10:
- today's goals: Complete all factor tests
- Meeting notes with Colin:
  - Next steps: completing all features and byte-level differential testing in JS bindings
  - remove todos, clean up rust architecture, start adding docs.

07-10:
- TODO: where to move `PolicyFactor` and is it even necessary?
- TODO: uniffi doesn't support record field renaming. can we allow that?
- TODO: more use of generics and impl types.
- created two simple PRs with refactoring today. async test removal and bindings feature.
- next refactoring: trait associated type and results
- clean up bindings api facade
- updating README with docs for setup and tests
- TODO: criterion bechmarks

```
my trait and strut system looks like:

- trait: `FactorSetup`, `FactorDerive`
```
#[allow(unused_variables)]
pub trait FactorDerive: Send + Sync + std::fmt::Debug {
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()>;
  fn params(&self, key: Key) -> MFKDF2Result<Value> { Ok(serde_json::json!({})) }
  fn output(&self) -> Value { serde_json::json!({}) }
}
```

- struct: `Mfkdf2Factor`
```
#[derive(Clone, Serialize, Deserialize)]
pub struct MFKDF2Factor {
  pub id:          Option<String>,
  pub factor_type: FactorType,
  pub salt:        Vec<u8>,
  pub entropy:     Option<f64>,
}
```

- enum `FactorType`:
```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FactorType {
  Password(password::Password),
  HOTP(hotp::HOTP),
  Question(question::Question),
  UUID(uuid::UUIDFactor),
  HmacSha1(hmacsha1::HmacSha1),
  TOTP(totp::TOTP),
  OOBA(ooba::Ooba),
  Passkey(passkey::Passkey),
  Stack(stack::Stack),
}
```

- each factor inside `FactorType` implements `FactorSetup` and `FactorDerive` trait.
- and to expose this functionality to factortype, i've implemented `FactorSetup` and `FactorDerive` trait for `FactorType` as well.
```
impl FactorType {
  pub fn setup(&self) -> &dyn FactorSetup<Output = Value> {
    match self {
      FactorType::Password(password) => password,
      FactorType::HOTP(hotp) => hotp,
      FactorType::Question(question) => question,
      FactorType::UUID(uuid) => uuid,
      FactorType::HmacSha1(hmacsha1) => hmacsha1,
      FactorType::TOTP(totp) => totp,
      FactorType::OOBA(ooba) => ooba,
      FactorType::Passkey(passkey) => passkey,
      FactorType::Stack(stack) => stack,
    }
  }
}

impl FactorSetup for FactorType {
  type Output = Value;

  fn bytes(&self) -> Vec<u8> { self.setup().bytes() }

  fn params(&self, key: Key) -> MFKDF2Result<Value> { self.setup().params(key) }

  fn output(&self, key: Key) -> Self::Output { self.setup().output(key) }
}

impl FactorType {
  fn derive(&self) -> &dyn FactorDerive {
    match self {
      FactorType::Password(password) => password,
      FactorType::HOTP(hotp) => hotp,
      FactorType::Question(question) => question,
      FactorType::UUID(uuid) => uuid,
      FactorType::HmacSha1(hmacsha1) => hmacsha1,
      FactorType::TOTP(totp) => totp,
      FactorType::OOBA(ooba) => ooba,
      FactorType::Passkey(passkey) => passkey,
      FactorType::Stack(stack) => stack,
    }
  }

  fn derive_mut(&mut self) -> &mut dyn FactorDerive {
    match self {
      FactorType::Password(password) => password,
      FactorType::HOTP(hotp) => hotp,
      FactorType::Question(question) => question,
      FactorType::UUID(uuid) => uuid,
      FactorType::HmacSha1(hmacsha1) => hmacsha1,
      FactorType::TOTP(totp) => totp,
      FactorType::OOBA(ooba) => ooba,
      FactorType::Passkey(passkey) => passkey,
      FactorType::Stack(stack) => stack,
    }
  }
}

impl FactorDerive for FactorType {
  // TODO: add associated types for params
  fn include_params(&mut self, params: Value) -> MFKDF2Result<()> {
    self.derive_mut().include_params(params)
  }

  fn params(&self, key: Key) -> MFKDF2Result<Value> { self.derive().params(key) }

  fn output(&self) -> Value { self.derive().output() }
}
```

- and then I usage looks like:
```
let factor = hotp(options)?;
let params = factor.factor_type.setup().params(key.into())?;
```

But i don't like this structure, due to following reasons:
- My goal is to add associated type for params for each factor. that is `FactorSetup` has a `Params` type and similarly for `FactorDerive`. But since `.setup` and `.derive, .derive_mut` return trait object i'll have to supply a `Params = T` object when implementing `FactorSetup` for `FactorType` like i already do for `Output` type.

Your goal is to find a solution to this that achieve the above goal, and provide beautiful, easily extensible architecture. Also give me reasons, on how i could've created it perfectly during first implementation.
```

Solution:
```
awesome — here’s a macro that generates **everything** you need from a single factor list:

* `FactorType` enum (payload = concrete factor type)
* sum types: `SetupParams`, `SetupOutput`, `DeriveParams`, `DeriveOutput`
* a `FactorKind` tag enum (handy for switches/logging)
* delegating methods on `FactorType` that return the sum types
* safe `include_derive_params(...)` that enforces variant matching at compile time
* a tiny visitor trait (optional but nice)

Just drop this in a module where `FactorSetup`, `FactorDerive`, `Key`, `MFKDF2Result` are in scope.

```rust
/// Define your factor universe in one place and get the whole plumbing.
///
/// Each entry is: Variant(ConcreteTypePath)
///
/// Example:
/// define_factors!{
///     Password(password::Password),
///     HOTP(hotp::HOTP),
///     Question(question::Question),
///     UUID(uuid::UUIDFactor),
///     HmacSha1(hmacsha1::HmacSha1),
///     TOTP(totp::TOTP),
///     OOBA(ooba::Ooba),
///     Passkey(passkey::Passkey),
///     Stack(stack::Stack),
/// }
#[macro_export]
macro_rules! define_factors {
    ($($Variant:ident ( $Ty:path )),+ $(,)?) => {
        use serde::{Serialize, Deserialize};
        use core::fmt::Debug;

        // ----------------------------
        // 1) The main enum (closed set)
        // ----------------------------
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub enum FactorType { $( $Variant($Ty), )+ }

        /// Tag enum (no payload). Great for logging / switches / metrics.
        #[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
        pub enum FactorKind { $( $Variant, )+ }

        impl FactorType {
            pub fn kind(&self) -> FactorKind {
                match self {
                    $( FactorType::$Variant(_) => FactorKind::$Variant, )+
                }
            }
        }

        // ------------------------------------------------------
        // 2) Sum types: keep strongly-typed params & outputs!
        //    We reference associated types directly from the impls.
        // ------------------------------------------------------
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub enum SetupParams { $(
            $Variant(<$Ty as $crate::FactorSetup>::Params),
        )+ }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub enum SetupOutput { $(
            $Variant(<$Ty as $crate::FactorSetup>::Output),
        )+ }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub enum DeriveParams { $(
            $Variant(<$Ty as $crate::FactorDerive>::Params),
        )+ }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub enum DeriveOutput { $(
            $Variant(<$Ty as $crate::FactorDerive>::Output),
        )+ }

        // ----------------------------------------------
        // 3) Delegating methods on FactorType
        //    (No trait-object erasure; returns sum types.)
        // ----------------------------------------------
        impl FactorType {
            #[inline]
            pub fn bytes(&self) -> Vec<u8> {
                match self {
                    $( FactorType::$Variant(x) => x.bytes(), )+
                }
            }

            #[inline]
            pub fn setup_params(&self, key: $crate::Key) -> $crate::MFKDF2Result<SetupParams> {
                Ok(match self {
                    $( FactorType::$Variant(x) => SetupParams::$Variant($crate::FactorSetup::params(x, key)?), )+
                })
            }

            #[inline]
            pub fn setup_output(&self, key: $crate::Key) -> $crate::MFKDF2Result<SetupOutput> {
                Ok(match self {
                    $( FactorType::$Variant(x) => SetupOutput::$Variant($crate::FactorSetup::output(x, key)?), )+
                })
            }

            #[inline]
            pub fn derive_params(&self, key: $crate::Key) -> $crate::MFKDF2Result<DeriveParams> {
                Ok(match self {
                    $( FactorType::$Variant(x) => DeriveParams::$Variant($crate::FactorDerive::params(x, key)?), )+
                })
            }

            #[inline]
            pub fn derive_output(&self) -> $crate::MFKDF2Result<DeriveOutput> {
                Ok(match self {
                    $( FactorType::$Variant(x) => DeriveOutput::$Variant($crate::FactorDerive::output(x)?), )+
                })
            }

            /// Include derive params in a type-safe way. Mismatched variant = error.
            #[inline]
            pub fn include_derive_params(&mut self, p: DeriveParams) -> $crate::MFKDF2Result<()> {
                match (self, p) {
                    $( (FactorType::$Variant(x), DeriveParams::$Variant(p)) => {
                        $crate::FactorDerive::include_params(x, p)
                    } ),+,
                    _ => Err($crate::err!("factor/params variant mismatch")),
                }
            }
        }

        // -----------------------------
        // 4) Small ergonomic niceties
        // -----------------------------
        /// A visitor so callers can write exhaustive logic without manual `match`es.
        pub trait FactorVisitor<R> {
            $( fn $Variant(&mut self, v: &$Ty) -> R; )+
        }

        impl FactorType {
            pub fn visit<R>(&self, mut v: impl FactorVisitor<R>) -> R {
                match self {
                    $( FactorType::$Variant(x) => v.$Variant(x), )+
                }
            }
        }

        // TryFrom helpers to extract the concrete params/outputs when you know the kind.
        $(
        impl ::core::convert::TryFrom<SetupParams> for <$Ty as $crate::FactorSetup>::Params {
            type Error = &'static str;
            fn try_from(p: SetupParams) -> Result<Self, Self::Error> {
                if let SetupParams::$Variant(x) = p { Ok(x) } else { Err("wrong SetupParams variant") }
            }
        }
        impl ::core::convert::TryFrom<SetupOutput> for <$Ty as $crate::FactorSetup>::Output {
            type Error = &'static str;
            fn try_from(p: SetupOutput) -> Result<Self, Self::Error> {
                if let SetupOutput::$Variant(x) = p { Ok(x) } else { Err("wrong SetupOutput variant") }
            }
        }
        impl ::core::convert::TryFrom<DeriveParams> for <$Ty as $crate::FactorDerive>::Params {
            type Error = &'static str;
            fn try_from(p: DeriveParams) -> Result<Self, Self::Error> {
                if let DeriveParams::$Variant(x) = p { Ok(x) } else { Err("wrong DeriveParams variant") }
            }
        }
        impl ::core::convert::TryFrom<DeriveOutput> for <$Ty as $crate::FactorDerive>::Output {
            type Error = &'static str;
            fn try_from(p: DeriveOutput) -> Result<Self, Self::Error> {
                if let DeriveOutput::$Variant(x) = p { Ok(x) } else { Err("wrong DeriveOutput variant") }
            }
        }
        )+
    };
}
```

### Use it like this

```rust
// your typed traits (as we aligned earlier)
pub trait FactorSetup: Send + Sync + Debug + 'static {
    type Params: Serialize + for<'de> Deserialize<'de> + Debug;
    type Output: Serialize + for<'de> Deserialize<'de> + Debug;

    fn bytes(&self) -> Vec<u8>;
    fn params(&self, key: Key) -> MFKDF2Result<Self::Params>;
    fn output(&self, key: Key) -> MFKDF2Result<Self::Output>;
}

pub trait FactorDerive: Send + Sync + Debug + 'static {
    type Params: Serialize + for<'de> Deserialize<'de> + Debug;
    type Output: Serialize + for<'de> Deserialize<'de> + Debug;

    fn include_params(&mut self, params: Self::Params) -> MFKDF2Result<()>;
    fn params(&self, key: Key) -> MFKDF2Result<Self::Params>;
    fn output(&self) -> MFKDF2Result<Self::Output>;
}

// ---- generate all enums + impls in one shot
define_factors! {
    Password(password::Password),
    HOTP(hotp::HOTP),
    Question(question::Question),
    UUID(uuid::UUIDFactor),
    HmacSha1(hmacsha1::HmacSha1),
    TOTP(totp::TOTP),
    OOBA(ooba::Ooba),
    Passkey(passkey::Passkey),
    Stack(stack::Stack),
}
```

### Call sites stay tidy

```rust
let factor = hotp(options)?; // -> your MFKDF2Factor
let params = factor.factor_type.setup_params(key.into())?;

match params {
    SetupParams::HOTP(p) => { /* p: hotp::Params */ }
    _ => unreachable!("we know it's HOTP here"),
}

let out = factor.factor_type.setup_output(key.into())?;
let hotp_out: <hotp::HOTP as FactorSetup>::Output = out.try_into().unwrap();
```

---

### Why this hits your goals

* **One set of traits**; no duplicated “erased” layer.
* **Strong typing preserved** end-to-end via associated types and **sum-type returns**.
* **Extensible**: add a factor by touching a single macro invocation line.
* **No `serde_json::Value`** anywhere unless you choose to serialize the enums.
* **Beautiful**: closed-world enum + generated sum types is idiomatic for Rust when associated types differ per variant.

If you want, I can also add a helper macro to forward `impl FactorSetup/FactorDerive` for each factor, but most of that stays in each module anyway.
```

Pending things for milestone 2:
- [x] merge bindings PR, address Colin comments
- [x] complete leftover features from reference implementation along with tests
  - reconstitution
  - hint
  - strengthening
  - stage
- byte-level validation of tests in bindings and rust
- [x] fix totp test failure
- [x] fix mocha reports not getting generating
- [x] IGNORE: add web tests to gitignore or generate them otf

## Uniffi

- Support of zero-copy: https://github.com/mozilla/uniffi-rs/issues/2208
- 