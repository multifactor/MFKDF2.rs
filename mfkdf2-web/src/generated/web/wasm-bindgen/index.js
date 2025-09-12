let wasm;

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_export_2.set(idx, obj);
    return idx;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

let cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

function isLikeNone(x) {
    return x === undefined || x === null;
}
/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_void(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_void(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_u64(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_u64(handle);
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {Uint8Array}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_rust_buffer(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_rust_buffer(handle, f_status_.__wbg_ptr);
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * @returns {number}
 */
export function ubrn_uniffi_mfkdf2_checksum_func_hotp() {
    const ret = wasm.ubrn_uniffi_mfkdf2_checksum_func_hotp();
    return ret;
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_u8(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_u8(handle);
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_i32(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_i32(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {bigint}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_pointer(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_pointer(handle, f_status_.__wbg_ptr);
    return BigInt.asUintN(64, ret);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_i32(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_i32(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_u64(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_u64(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_u8(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_u8(handle);
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
 * @param {Uint8Array} factors
 * @param {Uint8Array} options
 * @returns {bigint}
 */
export function ubrn_uniffi_mfkdf2_fn_func_key(factors, options) {
    const ptr0 = passArray8ToWasm0(factors, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(options, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.ubrn_uniffi_mfkdf2_fn_func_key(ptr0, len0, ptr1, len1);
    return BigInt.asUintN(64, ret);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_f64(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_f64(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_i8(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_i8(handle);
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_void(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    wasm.ubrn_ffi_mfkdf2_rust_future_complete_void(handle, f_status_.__wbg_ptr);
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_u16(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_u16(handle, callback, callback_data);
}

/**
 * @param {Uint8Array} password
 * @param {Uint8Array} options
 * @param {RustCallStatus} f_status_
 * @returns {Uint8Array}
 */
export function ubrn_uniffi_mfkdf2_fn_func_setup_password(password, options, f_status_) {
    const ptr0 = passArray8ToWasm0(password, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(options, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_uniffi_mfkdf2_fn_func_setup_password(ptr0, len0, ptr1, len1, f_status_.__wbg_ptr);
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_u8(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_u8(handle, f_status_.__wbg_ptr);
    return ret;
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_f64(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_f64(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_i64(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_i64(handle);
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_i16(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_i16(handle, f_status_.__wbg_ptr);
    return ret;
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_i8(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_i8(handle, f_status_.__wbg_ptr);
    return ret;
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {bigint}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_i64(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_i64(handle, f_status_.__wbg_ptr);
    return ret;
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {bigint}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_u64(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_u64(handle, f_status_.__wbg_ptr);
    return BigInt.asUintN(64, ret);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_i16(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_i16(handle);
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_f64(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_f64(handle, f_status_.__wbg_ptr);
    return ret;
}

/**
 * @returns {number}
 */
export function ubrn_uniffi_mfkdf2_checksum_func_key() {
    const ret = wasm.ubrn_uniffi_mfkdf2_checksum_func_key();
    return ret;
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_i16(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_i16(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_i64(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_i64(handle);
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_void(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_void(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_f64(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_f64(handle);
}

/**
 * @returns {number}
 */
export function ubrn_uniffi_mfkdf2_checksum_func_derive_key() {
    const ret = wasm.ubrn_uniffi_mfkdf2_checksum_func_derive_key();
    return ret;
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_f32(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_f32(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_u64(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_u64(handle, callback, callback_data);
}

/**
 * @param {Uint8Array} password
 * @param {RustCallStatus} f_status_
 * @returns {Uint8Array}
 */
export function ubrn_uniffi_mfkdf2_fn_func_derive_password(password, f_status_) {
    const ptr0 = passArray8ToWasm0(password, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_uniffi_mfkdf2_fn_func_derive_password(ptr0, len0, f_status_.__wbg_ptr);
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * @param {number} code
 * @param {RustCallStatus} f_status_
 * @returns {Uint8Array}
 */
export function ubrn_uniffi_mfkdf2_fn_func_hotp(code, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_uniffi_mfkdf2_fn_func_hotp(code, f_status_.__wbg_ptr);
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_rust_buffer(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_rust_buffer(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_void(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_void(handle);
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_i16(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_i16(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_pointer(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_pointer(handle);
}

/**
 * @returns {number}
 */
export function ubrn_uniffi_mfkdf2_checksum_func_setup_password() {
    const ret = wasm.ubrn_uniffi_mfkdf2_checksum_func_setup_password();
    return ret;
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_f32(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_f32(handle, f_status_.__wbg_ptr);
    return ret;
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_f32(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_f32(handle);
}

/**
 * @param {Uint8Array} policy
 * @param {Uint8Array} factors
 * @returns {bigint}
 */
export function ubrn_uniffi_mfkdf2_fn_func_derive_key(policy, factors) {
    const ptr0 = passArray8ToWasm0(policy, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(factors, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.ubrn_uniffi_mfkdf2_fn_func_derive_key(ptr0, len0, ptr1, len1);
    return BigInt.asUintN(64, ret);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_u16(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_u16(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_i32(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_i32(handle);
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_i8(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_i8(handle, callback, callback_data);
}

/**
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_uniffi_contract_version() {
    const ret = wasm.ubrn_ffi_mfkdf2_uniffi_contract_version();
    return ret >>> 0;
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_i64(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_i64(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_rust_buffer(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_rust_buffer(handle);
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_u32(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_u32(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_f32(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_f32(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_i8(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_i8(handle);
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_u32(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_u32(handle, f_status_.__wbg_ptr);
    return ret >>> 0;
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_u16(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_u16(handle, f_status_.__wbg_ptr);
    return ret;
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_u8(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_u8(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_rust_buffer(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_rust_buffer(handle, callback, callback_data);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_u16(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_u16(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_u32(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_u32(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_free_u32(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_free_u32(handle);
}

/**
 * @param {bigint} handle
 */
export function ubrn_ffi_mfkdf2_rust_future_cancel_pointer(handle) {
    wasm.ubrn_ffi_mfkdf2_rust_future_cancel_pointer(handle);
}

/**
 * @param {bigint} handle
 * @param {RustCallStatus} f_status_
 * @returns {number}
 */
export function ubrn_ffi_mfkdf2_rust_future_complete_i32(handle, f_status_) {
    _assertClass(f_status_, RustCallStatus);
    const ret = wasm.ubrn_ffi_mfkdf2_rust_future_complete_i32(handle, f_status_.__wbg_ptr);
    return ret;
}

/**
 * @param {bigint} handle
 * @param {any} callback
 * @param {bigint} callback_data
 */
export function ubrn_ffi_mfkdf2_rust_future_poll_pointer(handle, callback, callback_data) {
    wasm.ubrn_ffi_mfkdf2_rust_future_poll_pointer(handle, callback, callback_data);
}

/**
 * @returns {number}
 */
export function ubrn_uniffi_mfkdf2_checksum_func_derive_password() {
    const ret = wasm.ubrn_uniffi_mfkdf2_checksum_func_derive_password();
    return ret;
}

const RustCallStatusFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_rustcallstatus_free(ptr >>> 0, 1));

export class RustCallStatus {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        RustCallStatusFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_rustcallstatus_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    get code() {
        const ret = wasm.__wbg_get_rustcallstatus_code(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {number} arg0
     */
    set code(arg0) {
        wasm.__wbg_set_rustcallstatus_code(this.__wbg_ptr, arg0);
    }
    constructor() {
        const ret = wasm.rustcallstatus_new();
        this.__wbg_ptr = ret >>> 0;
        RustCallStatusFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {Uint8Array | null} [bytes]
     */
    set errorBuf(bytes) {
        var ptr0 = isLikeNone(bytes) ? 0 : passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.rustcallstatus_set_error_buf(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @returns {Uint8Array | undefined}
     */
    get errorBuf() {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.rustcallstatus_error_buf(ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
}

const EXPECTED_RESPONSE_TYPES = new Set(['basic', 'cors', 'default']);

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                const validResponse = module.ok && EXPECTED_RESPONSE_TYPES.has(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_buffer_a1a27a0dfa70165d = function(arg0) {
        const ret = arg0.buffer;
        return ret;
    };
    imports.wbg.__wbg_call_1b4346259a9fb9a0 = function(arg0, arg1, arg2, arg3) {
        arg0.call(arg1, BigInt.asUintN(64, arg2), arg3);
    };
    imports.wbg.__wbg_call_f2db6205e5c51dc8 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = arg0.call(arg1, arg2);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_call_fbe8be8bf6436ce5 = function() { return handleError(function (arg0, arg1) {
        const ret = arg0.call(arg1);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_crypto_574e78ad8b13b65f = function(arg0) {
        const ret = arg0.crypto;
        return ret;
    };
    imports.wbg.__wbg_getFullYear_1383a5751fab658e = function(arg0) {
        const ret = arg0.getFullYear();
        return ret;
    };
    imports.wbg.__wbg_getRandomValues_b8f5dbd5f3995a9e = function() { return handleError(function (arg0, arg1) {
        arg0.getRandomValues(arg1);
    }, arguments) };
    imports.wbg.__wbg_msCrypto_a61aeb35a24c1329 = function(arg0) {
        const ret = arg0.msCrypto;
        return ret;
    };
    imports.wbg.__wbg_new0_97314565408dea38 = function() {
        const ret = new Date();
        return ret;
    };
    imports.wbg.__wbg_new_e52b3efaaa774f96 = function(arg0) {
        const ret = new Uint8Array(arg0);
        return ret;
    };
    imports.wbg.__wbg_newnoargs_ff528e72d35de39a = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_newwithbyteoffsetandlength_3b01ecda099177e8 = function(arg0, arg1, arg2) {
        const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_newwithlength_08f872dc1e3ada2e = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_node_905d3e251edff8a2 = function(arg0) {
        const ret = arg0.node;
        return ret;
    };
    imports.wbg.__wbg_now_7ab37f05ab2d0b81 = function(arg0) {
        const ret = arg0.now();
        return ret;
    };
    imports.wbg.__wbg_process_dc0fbacc7c1c06f7 = function(arg0) {
        const ret = arg0.process;
        return ret;
    };
    imports.wbg.__wbg_randomFillSync_ac0988aba3254290 = function() { return handleError(function (arg0, arg1) {
        arg0.randomFillSync(arg1);
    }, arguments) };
    imports.wbg.__wbg_require_60cc747a6bc5215a = function() { return handleError(function () {
        const ret = module.require;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_set_fe4e79d1ed3b0e9b = function(arg0, arg1, arg2) {
        arg0.set(arg1, arg2 >>> 0);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_487c52c58d65314d = function() {
        const ret = typeof global === 'undefined' ? null : global;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_THIS_ee9704f328b6b291 = function() {
        const ret = typeof globalThis === 'undefined' ? null : globalThis;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_SELF_78c9e3071b912620 = function() {
        const ret = typeof self === 'undefined' ? null : self;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_WINDOW_a093d21393777366 = function() {
        const ret = typeof window === 'undefined' ? null : window;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_performance_da77b3a901a72934 = function() {
        const ret = performance;
        return ret;
    };
    imports.wbg.__wbg_subarray_dd4ade7d53bd8e26 = function(arg0, arg1, arg2) {
        const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_versions_c01dfd4722a88165 = function(arg0) {
        const ret = arg0.versions;
        return ret;
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_export_2;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
        ;
    };
    imports.wbg.__wbindgen_is_function = function(arg0) {
        const ret = typeof(arg0) === 'function';
        return ret;
    };
    imports.wbg.__wbindgen_is_object = function(arg0) {
        const val = arg0;
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbindgen_is_string = function(arg0) {
        const ret = typeof(arg0) === 'string';
        return ret;
    };
    imports.wbg.__wbindgen_is_undefined = function(arg0) {
        const ret = arg0 === undefined;
        return ret;
    };
    imports.wbg.__wbindgen_memory = function() {
        const ret = wasm.memory;
        return ret;
    };
    imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
        const ret = getStringFromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }


    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
