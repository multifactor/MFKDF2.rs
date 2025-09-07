// Simple test for mfkdf2.setup.factors.password()
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import init, { setup_factors_password, setup_key, test_string_return } from './pkg/mfkdf2_wasm.js';
import { createMFKDF2 } from './api.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function test() {
    console.log('🧪 Testing MFKDF2 Setup: Password Factor + Key Creation');
    console.log('=====================================================');

    try {
        // Load and initialize WASM
        const wasmPath = path.join(__dirname, 'pkg', 'mfkdf2_wasm_bg.wasm');
        const wasmBytes = fs.readFileSync(wasmPath);
        const wasmModule = await init(wasmBytes);

        // Create API with wrapper functions
        const mfkdf2 = createMFKDF2(wasmModule, { setup_factors_password, setup_key });

        // Test 1: Create password factor
        console.log('📝 Creating password factor...');
        const factor = mfkdf2.setup.factors.password('Tr0ubd4dour', { id: 'password_1' });
        console.log('✅ Password factor created!');
        console.log(`   ID: ${factor.id}`);
        console.log(`   Type: ${factor.kind}`);
        console.log(`   Entropy: ${factor.entropy} bits`);
        console.log('   Full factor structure:', JSON.stringify(factor, null, 2));

        // Test 2: Create MFKDF2 key (like the Rust integration test)
        console.log('\n🔑 Creating MFKDF2 key...');
        const factors = [factor];
        const derivedKey = await mfkdf2.setup.key(factors);

        console.log('✅ MFKDF2 key created!');
        console.log(`   Policy: ${JSON.stringify(derivedKey.policy)}`);
        console.log(`   Key: ${derivedKey.key}`);

        return true;

    } catch (error) {
        console.error('❌ Test failed:', error.message);
        return false;
    }
}

test().then(success => {
    process.exit(success ? 0 : 1);
});
