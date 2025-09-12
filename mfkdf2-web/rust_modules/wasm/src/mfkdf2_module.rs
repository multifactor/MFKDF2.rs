#[allow(unused_imports)]
use uniffi_runtime_javascript::{self as js, uniffi as u, IntoJs, IntoRust};
use wasm_bindgen::prelude::wasm_bindgen;
extern "C" {
    fn uniffi_mfkdf2_fn_func_derive_key(
        policy: u::RustBuffer,
        factors: u::RustBuffer,
    ) -> u64;
    fn uniffi_mfkdf2_fn_func_derive_password(
        password: u::RustBuffer,
        status_: &mut u::RustCallStatus,
    ) -> u::RustBuffer;
    fn uniffi_mfkdf2_fn_func_hotp(
        code: u32,
        status_: &mut u::RustCallStatus,
    ) -> u::RustBuffer;
    fn uniffi_mfkdf2_fn_func_key(factors: u::RustBuffer, options: u::RustBuffer) -> u64;
    fn uniffi_mfkdf2_fn_func_setup_password(
        password: u::RustBuffer,
        options: u::RustBuffer,
        status_: &mut u::RustCallStatus,
    ) -> u::RustBuffer;
    fn ffi_mfkdf2_rust_future_poll_u8(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_u8(handle: u64);
    fn ffi_mfkdf2_rust_future_free_u8(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_u8(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> u8;
    fn ffi_mfkdf2_rust_future_poll_i8(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_i8(handle: u64);
    fn ffi_mfkdf2_rust_future_free_i8(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_i8(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> i8;
    fn ffi_mfkdf2_rust_future_poll_u16(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_u16(handle: u64);
    fn ffi_mfkdf2_rust_future_free_u16(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_u16(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> u16;
    fn ffi_mfkdf2_rust_future_poll_i16(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_i16(handle: u64);
    fn ffi_mfkdf2_rust_future_free_i16(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_i16(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> i16;
    fn ffi_mfkdf2_rust_future_poll_u32(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_u32(handle: u64);
    fn ffi_mfkdf2_rust_future_free_u32(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_u32(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> u32;
    fn ffi_mfkdf2_rust_future_poll_i32(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_i32(handle: u64);
    fn ffi_mfkdf2_rust_future_free_i32(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_i32(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> i32;
    fn ffi_mfkdf2_rust_future_poll_u64(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_u64(handle: u64);
    fn ffi_mfkdf2_rust_future_free_u64(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_u64(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> u64;
    fn ffi_mfkdf2_rust_future_poll_i64(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_i64(handle: u64);
    fn ffi_mfkdf2_rust_future_free_i64(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_i64(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> i64;
    fn ffi_mfkdf2_rust_future_poll_f32(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_f32(handle: u64);
    fn ffi_mfkdf2_rust_future_free_f32(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_f32(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> f32;
    fn ffi_mfkdf2_rust_future_poll_f64(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_f64(handle: u64);
    fn ffi_mfkdf2_rust_future_free_f64(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_f64(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> f64;
    fn ffi_mfkdf2_rust_future_poll_pointer(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_pointer(handle: u64);
    fn ffi_mfkdf2_rust_future_free_pointer(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_pointer(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> u::VoidPointer;
    fn ffi_mfkdf2_rust_future_poll_rust_buffer(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_rust_buffer(handle: u64);
    fn ffi_mfkdf2_rust_future_free_rust_buffer(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_rust_buffer(
        handle: u64,
        status_: &mut u::RustCallStatus,
    ) -> u::RustBuffer;
    fn ffi_mfkdf2_rust_future_poll_void(
        handle: u64,
        callback: rust_future_continuation_callback::FnSig,
        callback_data: u64,
    );
    fn ffi_mfkdf2_rust_future_cancel_void(handle: u64);
    fn ffi_mfkdf2_rust_future_free_void(handle: u64);
    fn ffi_mfkdf2_rust_future_complete_void(
        handle: u64,
        status_: &mut u::RustCallStatus,
    );
    fn uniffi_mfkdf2_checksum_func_derive_key() -> u16;
    fn uniffi_mfkdf2_checksum_func_derive_password() -> u16;
    fn uniffi_mfkdf2_checksum_func_hotp() -> u16;
    fn uniffi_mfkdf2_checksum_func_key() -> u16;
    fn uniffi_mfkdf2_checksum_func_setup_password() -> u16;
    fn ffi_mfkdf2_uniffi_contract_version() -> u32;
}
#[wasm_bindgen]
pub unsafe fn ubrn_uniffi_mfkdf2_fn_func_derive_key(
    policy: js::ForeignBytes,
    factors: js::ForeignBytes,
) -> js::Handle {
    uniffi_mfkdf2_fn_func_derive_key(
            u::RustBuffer::into_rust(policy),
            u::RustBuffer::into_rust(factors),
        )
        .into_js()
}
#[wasm_bindgen]
pub fn ubrn_uniffi_mfkdf2_fn_func_derive_password(
    password: js::ForeignBytes,
    f_status_: &mut js::RustCallStatus,
) -> js::ForeignBytes {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        uniffi_mfkdf2_fn_func_derive_password(
            u::RustBuffer::into_rust(password),
            &mut u_status_,
        )
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub fn ubrn_uniffi_mfkdf2_fn_func_hotp(
    code: js::UInt32,
    f_status_: &mut js::RustCallStatus,
) -> js::ForeignBytes {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        uniffi_mfkdf2_fn_func_hotp(u32::into_rust(code), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_uniffi_mfkdf2_fn_func_key(
    factors: js::ForeignBytes,
    options: js::ForeignBytes,
) -> js::Handle {
    uniffi_mfkdf2_fn_func_key(
            u::RustBuffer::into_rust(factors),
            u::RustBuffer::into_rust(options),
        )
        .into_js()
}
#[wasm_bindgen]
pub fn ubrn_uniffi_mfkdf2_fn_func_setup_password(
    password: js::ForeignBytes,
    options: js::ForeignBytes,
    f_status_: &mut js::RustCallStatus,
) -> js::ForeignBytes {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        uniffi_mfkdf2_fn_func_setup_password(
            u::RustBuffer::into_rust(password),
            u::RustBuffer::into_rust(options),
            &mut u_status_,
        )
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_u8(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_u8(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_u8(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_u8(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_u8(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_u8(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_u8(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::UInt8 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_u8(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_i8(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_i8(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_i8(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_i8(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_i8(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_i8(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_i8(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::Int8 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_i8(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_u16(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_u16(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_u16(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_u16(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_u16(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_u16(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_u16(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::UInt16 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_u16(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_i16(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_i16(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_i16(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_i16(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_i16(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_i16(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_i16(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::Int16 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_i16(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_u32(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_u32(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_u32(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_u32(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_u32(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_u32(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_u32(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::UInt32 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_u32(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_i32(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_i32(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_i32(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_i32(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_i32(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_i32(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_i32(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::Int32 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_i32(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_u64(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_u64(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_u64(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_u64(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_u64(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_u64(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_u64(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::UInt64 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_u64(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_i64(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_i64(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_i64(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_i64(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_i64(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_i64(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_i64(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::Int64 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_i64(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_f32(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_f32(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_f32(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_f32(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_f32(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_f32(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_f32(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::Float32 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_f32(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_f64(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_f64(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_f64(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_f64(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_f64(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_f64(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_f64(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::Float64 {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_f64(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_pointer(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_pointer(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_pointer(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_pointer(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_pointer(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_pointer(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_pointer(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::VoidPointer {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_pointer(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_rust_buffer(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_rust_buffer(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_rust_buffer(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_rust_buffer(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_rust_buffer(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_rust_buffer(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_rust_buffer(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) -> js::ForeignBytes {
    let mut u_status_ = u::RustCallStatus::default();
    let value_ = unsafe {
        ffi_mfkdf2_rust_future_complete_rust_buffer(
            u64::into_rust(handle),
            &mut u_status_,
        )
    };
    f_status_.copy_from(u_status_);
    value_.into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_poll_void(
    handle: js::Handle,
    callback: rust_future_continuation_callback::JsCallbackFn,
    callback_data: js::Handle,
) {
    ffi_mfkdf2_rust_future_poll_void(
        u64::into_rust(handle),
        rust_future_continuation_callback::FnSig::into_rust(callback),
        u64::into_rust(callback_data),
    );
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_cancel_void(handle: js::Handle) {
    ffi_mfkdf2_rust_future_cancel_void(u64::into_rust(handle));
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_rust_future_free_void(handle: js::Handle) {
    ffi_mfkdf2_rust_future_free_void(u64::into_rust(handle));
}
#[wasm_bindgen]
pub fn ubrn_ffi_mfkdf2_rust_future_complete_void(
    handle: js::Handle,
    f_status_: &mut js::RustCallStatus,
) {
    let mut u_status_ = u::RustCallStatus::default();
    unsafe {
        ffi_mfkdf2_rust_future_complete_void(u64::into_rust(handle), &mut u_status_)
    };
    f_status_.copy_from(u_status_);
}
#[wasm_bindgen]
pub unsafe fn ubrn_uniffi_mfkdf2_checksum_func_derive_key() -> js::UInt16 {
    uniffi_mfkdf2_checksum_func_derive_key().into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_uniffi_mfkdf2_checksum_func_derive_password() -> js::UInt16 {
    uniffi_mfkdf2_checksum_func_derive_password().into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_uniffi_mfkdf2_checksum_func_hotp() -> js::UInt16 {
    uniffi_mfkdf2_checksum_func_hotp().into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_uniffi_mfkdf2_checksum_func_key() -> js::UInt16 {
    uniffi_mfkdf2_checksum_func_key().into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_uniffi_mfkdf2_checksum_func_setup_password() -> js::UInt16 {
    uniffi_mfkdf2_checksum_func_setup_password().into_js()
}
#[wasm_bindgen]
pub unsafe fn ubrn_ffi_mfkdf2_uniffi_contract_version() -> js::UInt32 {
    ffi_mfkdf2_uniffi_contract_version().into_js()
}
mod rust_future_continuation_callback {
    use super::*;
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen]
        pub type JsCallbackFn;
        #[wasm_bindgen(method)]
        pub fn call(
            this_: &JsCallbackFn,
            ctx_: &JsCallbackFn,
            data: js::UInt64,
            poll_result: js::Int8,
        );
    }
    thread_local! {
        static CALLBACK : js::ForeignCell < JsCallbackFn > = js::ForeignCell::new();
    }
    impl IntoRust<JsCallbackFn> for FnSig {
        fn into_rust(callback: JsCallbackFn) -> Self {
            CALLBACK.with(|cell| cell.set(callback));
            implementation
        }
    }
    pub(super) type FnSig = extern "C" fn(data: u64, poll_result: i8);
    extern "C" fn implementation(data: u64, poll_result: i8) {
        CALLBACK
            .with(|cell_| {
                cell_
                    .with_value(|callback_| {
                        callback_.call(callback_, data.into_js(), poll_result.into_js())
                    })
            });
    }
}
