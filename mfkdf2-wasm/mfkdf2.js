/**
 * MFKDF2 JavaScript Wrapper for WASM
 * Provides the same API as the original MFKDF2.js library
 */

class MFKDF2 {
    constructor() {
        this.wasmModule = null;
        this.memory = null;
        this.textEncoder = new TextEncoder();
        this.textDecoder = new TextDecoder();
    }

    /**
     * Initialize the WASM module
     * @param {ArrayBuffer|Uint8Array} wasmBytes - The WASM binary
     */
    async init(wasmBytes) {
        const wasmModule = await WebAssembly.instantiate(wasmBytes, {
            env: {
                // Add any imports the WASM module needs
            }
        });

        this.wasmModule = wasmModule.instance;
        this.memory = this.wasmModule.exports.memory;

        return this;
    }

    /**
     * Allocate memory in WASM
     * @param {number} size - Size in bytes
     * @returns {number} Pointer to allocated memory
     */
    _alloc(size) {
        return this.wasmModule.exports.alloc(size);
    }

    /**
     * Deallocate memory in WASM
     * @param {number} ptr - Pointer to memory
     * @param {number} size - Size in bytes
     */
    _dealloc(ptr, size) {
        this.wasmModule.exports.dealloc(ptr, size);
    }

    /**
     * Write a string to WASM memory
     * @param {string} str - String to write
     * @returns {number} Pointer to the string in WASM memory
     */
    _writeString(str) {
        const bytes = this.textEncoder.encode(str + '\0'); // null-terminated
        const ptr = this._alloc(bytes.length);
        const memory = new Uint8Array(this.memory.buffer);
        memory.set(bytes, ptr);
        return ptr;
    }

    /**
     * Read a string from WASM memory
     * @param {number} ptr - Pointer to string in WASM memory
     * @returns {string} The string
     */
    _readString(ptr) {
        if (ptr === 0) return null;

        const memory = new Uint8Array(this.memory.buffer);
        let end = ptr;
        while (memory[end] !== 0) end++; // find null terminator

        const bytes = memory.slice(ptr, end);
        return this.textDecoder.decode(bytes);
    }

    /**
     * Free a string allocated by WASM
     * @param {number} ptr - Pointer to string
     */
    _freeString(ptr) {
        if (ptr !== 0) {
            this.wasmModule.exports.free_string(ptr);
        }
    }

    /**
     * Call a WASM function that returns a JSON string
     * @param {Function} wasmFn - WASM function to call
     * @param {...any} args - Arguments to pass to the function
     * @returns {any} Parsed JSON result
     */
    _callJsonFunction(wasmFn, ...args) {
        const resultPtr = wasmFn.call(this.wasmModule.exports, ...args);
        if (resultPtr === 0) {
            throw new Error('WASM function returned null');
        }

        const jsonStr = this._readString(resultPtr);
        this._freeString(resultPtr);

        if (!jsonStr) {
            throw new Error('Failed to read result from WASM');
        }

        try {
            return JSON.parse(jsonStr);
        } catch (e) {
            throw new Error(`Failed to parse JSON result: ${jsonStr}`);
        }
    }

    // ============================================================================
    // Setup API - matches original MFKDF2.js structure
    // ============================================================================

    get setup() {
        return {
            /**
             * Setup a multi-factor derived key
             * @param {Array} factors - Array of factors
             * @param {Object} options - Setup options
             * @returns {Promise<Object>} Derived key object
             */
            key: async (factors, options = {}) => {
                const factorsJson = JSON.stringify(factors);
                const optionsJson = JSON.stringify(options);

                const factorsPtr = this._writeString(factorsJson);
                const optionsPtr = this._writeString(optionsJson);

                try {
                    // Note: We need to implement setup_key in WASM first
                    // For now, let's implement a simpler version
                    throw new Error('setup_key not yet implemented in WASM');
                } finally {
                    this._dealloc(factorsPtr, factorsJson.length + 1);
                    this._dealloc(optionsPtr, optionsJson.length + 1);
                }
            },

            factors: {
                /**
                 * Create a password factor for setup
                 * @param {string} password - The password
                 * @param {Object} options - Factor options
                 * @returns {Object} Password factor
                 */
                password: (password, options = {}) => {
                    const passwordPtr = this._writeString(password);
                    const idPtr = options.id ? this._writeString(options.id) : 0;

                    try {
                        const result = this._callJsonFunction(
                            this.wasmModule.exports.create_password_factor,
                            passwordPtr,
                            idPtr
                        );

                        return {
                            type: result.type,
                            id: result.id,
                            entropy: result.entropy,
                            // Add other properties as needed to match original API
                            _internal: result // Store full WASM result for internal use
                        };
                    } finally {
                        this._dealloc(passwordPtr, password.length + 1);
                        if (idPtr !== 0) {
                            this._dealloc(idPtr, options.id.length + 1);
                        }
                    }
                }
            }
        };
    }

    // ============================================================================
    // Derive API - matches original MFKDF2.js structure  
    // ============================================================================

    get derive() {
        return {
            /**
             * Derive a key from policy and factors
             * @param {Object} policy - The policy object
             * @param {Object} factors - Map of factor ID to factor function
             * @returns {Promise<Object>} Derived key object
             */
            key: async (policy, factors) => {
                // For now, implement simple password-only derivation
                const factorEntries = Object.entries(factors);
                if (factorEntries.length !== 1) {
                    throw new Error('Currently only single password factor supported');
                }

                const [factorId, factorFn] = factorEntries[0];

                // Assume it's a password factor function that returns the password
                const password = factorFn(); // This should return the password string

                const policyJson = JSON.stringify(policy);
                const policyPtr = this._writeString(policyJson);
                const passwordPtr = this._writeString(password);
                const factorIdPtr = this._writeString(factorId);

                try {
                    // Note: We need to implement derive_key_with_password in WASM first
                    throw new Error('derive_key_with_password not yet implemented in WASM');
                } finally {
                    this._dealloc(policyPtr, policyJson.length + 1);
                    this._dealloc(passwordPtr, password.length + 1);
                    this._dealloc(factorIdPtr, factorId.length + 1);
                }
            },

            factors: {
                /**
                 * Create a password factor for derivation
                 * @param {string} password - The password
                 * @returns {Function} Factor function
                 */
                password: (password) => {
                    return () => password; // Return a function that returns the password
                }
            }
        };
    }
}

// ============================================================================
// Module exports - matches original MFKDF2.js structure
// ============================================================================

/**
 * Initialize MFKDF2 with WASM binary
 * @param {ArrayBuffer|Uint8Array} wasmBytes - The WASM binary
 * @returns {Promise<Object>} MFKDF2 API object
 */
async function initMFKDF2(wasmBytes) {
    const mfkdf2 = new MFKDF2();
    await mfkdf2.init(wasmBytes);

    return {
        setup: mfkdf2.setup,
        derive: mfkdf2.derive,
        // Add other namespaces as needed
    };
}

// For Node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { initMFKDF2, MFKDF2 };
}

// For browsers
if (typeof window !== 'undefined') {
    window.MFKDF2 = { initMFKDF2, MFKDF2 };
}
