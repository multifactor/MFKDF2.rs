class MFKDF2 {
    constructor(wasmModule, wasmFunctions) {
        this.wasm = wasmModule;
        this.wasmFunctions = wasmFunctions;
    }

    get setup() {
        return {
            factors: {
                /**
                 * Create a password factor
                 * @param {string} password - The password
                 * @param {Object} [options] - Options
                 * @param {string} [options.id] - Factor ID
                 * @returns {Object} Password factor
                 */
                password: (password, options = {}) => {
                    const resultJson = this.wasmFunctions.setup_factors_password(password, options.id || null);
                    return JSON.parse(resultJson);
                }
            }
        };
    }
}

/**
 * Initialize MFKDF2 with WASM module and functions
 * @param {Object} wasmModule - The loaded WASM module
 * @param {Object} wasmFunctions - The WASM wrapper functions
 * @returns {Object} MFKDF2 API with setup.factors.password
 */
function createMFKDF2(wasmModule, wasmFunctions) {
    const api = new MFKDF2(wasmModule, wasmFunctions);
    return {
        setup: api.setup
    };
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { createMFKDF2 };
} else if (typeof window !== 'undefined') {
    window.MFKDF2 = { createMFKDF2 };
}

export { createMFKDF2 };
