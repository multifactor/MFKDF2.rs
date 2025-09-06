// Simple test for our pure WASM + JS wrapper approach
const fs = require('fs');
const path = require('path');
const { initMFKDF2 } = require('./mfkdf2.js');

async function test() {
    console.log('🧪 Testing MFKDF2 Pure WASM + JS Wrapper');
    console.log('==========================================');

    try {
        // Load the WASM binary
        const wasmPath = path.join(__dirname, '../target/wasm32-unknown-unknown/release/mfkdf2_wasm.wasm');

        if (!fs.existsSync(wasmPath)) {
            console.error('❌ WASM file not found at:', wasmPath);
            console.log('   Run: cargo build --target wasm32-unknown-unknown --release');
            return;
        }

        const wasmBytes = fs.readFileSync(wasmPath);
        console.log(`✅ Loaded WASM binary: ${wasmBytes.length} bytes`);

        // Initialize MFKDF2
        const mfkdf2 = await initMFKDF2(wasmBytes);
        console.log('✅ MFKDF2 initialized successfully');

        // Test password factor creation
        console.log('\n📝 Testing password factor creation...');
        const passwordFactor = mfkdf2.setup.factors.password('testpassword123', { id: 'password' });
        console.log('✅ Password factor created:');
        console.log(`   ID: ${passwordFactor.id}`);
        console.log(`   Type: ${passwordFactor.type}`);
        console.log(`   Entropy: ${passwordFactor.entropy} bits`);

        console.log('\n🎉 Basic test completed successfully!');
        console.log('\nNext steps:');
        console.log('- Implement setup_key in WASM');
        console.log('- Implement derive_key_with_password in WASM');
        console.log('- Add support for multiple factor types');

    } catch (error) {
        console.error('❌ Test failed:', error.message);
        console.error(error.stack);
    }
}

if (require.main === module) {
    test();
}

module.exports = { test };
