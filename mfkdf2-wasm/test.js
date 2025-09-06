// Simple test for mfkdf2.setup.factors.password()
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import init, { setup_factors_password, test_string_return } from './pkg/mfkdf2_wasm.js';
import { createMFKDF2 } from './api.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function test() {
    console.log('🧪 Testing mfkdf2.setup.factors.password()');
    console.log('========================================');

    try {
        // Load and initialize WASM
        const wasmPath = path.join(__dirname, 'pkg', 'mfkdf2_wasm_bg.wasm');
        const wasmBytes = fs.readFileSync(wasmPath);
        const wasmModule = await init(wasmBytes);

        // Create API with wrapper functions
        const mfkdf2 = createMFKDF2(wasmModule, { setup_factors_password });

        // Test the function
        console.log('📝 Creating password factor...');
        const factor = mfkdf2.setup.factors.password('testpassword123', { id: 'password' });

        console.log('✅ Success!');
        console.log(`   ID: ${factor.id}`);
        console.log(`   Type: ${factor.kind}`);
        console.log(`   Entropy: ${factor.entropy} bits`);

        return true;

    } catch (error) {
        console.error('❌ Test failed:', error.message);
        return false;
    }
}

test().then(success => {
    process.exit(success ? 0 : 1);
});
