class MFKDF2 {
    constructor(wasmModule, wasmFunctions) {
        this.wasm = wasmModule;
        this.wasmFunctions = wasmFunctions;
    }

    get setup() {
        return {
            /**
             * Create an MFKDF2 key from factors
             * @param {Array} factors - Array of MFKDF2Factor objects
             * @param {Object} [options] - Setup options
             * @returns {Promise<Object>} MFKDF2 derived key
             */
            key: async (factors, options = {}) => {
                const factorsJson = JSON.stringify(factors);
                const optionsJson = Object.keys(options).length > 0 ? JSON.stringify(options) : null;
                const resultJson = await this.wasmFunctions.setup_key(factorsJson, optionsJson);
                return JSON.parse(resultJson);
            },

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

    get derive() {
        return {
            /**
             * Derive an MFKDF2 key from policy and factors
             * @param {Object} policy - The MFKDF2 policy from setup
             * @param {Object} factors - HashMap of factor ID -> MFKDF2Factor
             * @returns {Promise<Object>} MFKDF2 derived key
             */
            key: async (policy, factors) => {
                const policyJson = JSON.stringify(policy);
                const factorsJson = JSON.stringify(factors);
                const resultJson = await this.wasmFunctions.derive_key(policyJson, factorsJson);
                return JSON.parse(resultJson);
            },

            factors: {
                /**
                 * Create a derive password factor
                 * @param {string} password - The password
                 * @returns {Object} Derive password factor
                 */
                password: (password) => {
                    const resultJson = this.wasmFunctions.derive_factors_password(password);
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
        setup: api.setup,
        derive: api.derive
    };
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { createMFKDF2 };
} else if (typeof window !== 'undefined') {
    window.MFKDF2 = { createMFKDF2 };
}

export { createMFKDF2 };
