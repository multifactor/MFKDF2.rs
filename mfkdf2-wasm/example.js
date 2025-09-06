// Node.js example for MFKDF2 WASM bindings
// Run with: node example.js

const fs = require('fs');
const path = require('path');

async function loadWasm() {
    const {
        default: init,
        setup_key,
        setup_password_factor,
        derive_key_with_password,
        DeriveFactorManager,
        derive_key,
        MFKDFOptions,
        set_panic_hook,
        console_log
    } = await import('./pkg/mfkdf2_wasm.js');

    // Initialize WASM with the binary
    const wasmPath = path.join(__dirname, 'pkg', 'mfkdf2_wasm_bg.wasm');
    const wasmBytes = fs.readFileSync(wasmPath);
    await init(wasmBytes);

    return {
        setup_key,
        setup_password_factor,
        derive_key_with_password,
        DeriveFactorManager,
        derive_key,
        MFKDFOptions,
        set_panic_hook,
        console_log
    };
}

async function basicExample() {
    console.log('🔐 MFKDF2 WASM Basic Example');
    console.log('================================');

    // Load WASM module
    const wasm = await loadWasm();
    const { setup_key, setup_password_factor, derive_key_with_password, MFKDFOptions, set_panic_hook } = wasm;

    // Set up panic hook for better error messages
    set_panic_hook();

    try {
        // Step 1: Create a password factor
        console.log('📝 Creating password factor...');
        const passwordFactor = setup_password_factor("mypassword123", "password");
        console.log(`   Factor ID: ${passwordFactor.id}`);
        console.log(`   Factor type: ${passwordFactor.type}`);
        console.log(`   Entropy: ${passwordFactor.entropy} bits`);

        // Step 2: Set up options
        console.log('\n⚙️  Setting up options...');
        const options = new MFKDFOptions();
        options.set_threshold(1);
        options.set_id("example-key-001");

        // Step 3: Setup the key
        console.log('\n🔑 Setting up MFKDF2 key...');
        const setupKey = await setup_key([passwordFactor], options);

        console.log(`   Key: ${Buffer.from(setupKey.key).toString('hex')}`);
        console.log(`   Secret: ${Buffer.from(setupKey.secret).toString('hex')}`);

        // Step 4: Parse and display policy
        const policy = JSON.parse(setupKey.policy);
        console.log('\n📋 Policy:');
        console.log(`   Schema: ${policy.$schema}`);
        console.log(`   ID: ${policy.$id}`);
        console.log(`   Threshold: ${policy.threshold}`);
        console.log(`   Factors: ${policy.factors.length}`);

        // Step 5: Derive key using password
        console.log('\n🔓 Deriving key with password...');
        const derivedKey = await derive_key_with_password(
            setupKey.policy,
            "mypassword123",
            "password"
        );

        console.log(`   Derived Key: ${Buffer.from(derivedKey.key).toString('hex')}`);
        console.log(`   Derived Secret: ${Buffer.from(derivedKey.secret).toString('hex')}`);

        // Step 6: Verify keys match
        const setupKeyHex = Buffer.from(setupKey.key).toString('hex');
        const derivedKeyHex = Buffer.from(derivedKey.key).toString('hex');

        if (setupKeyHex === derivedKeyHex) {
            console.log('\n✅ SUCCESS: Setup and derived keys match!');
        } else {
            console.log('\n❌ ERROR: Keys do not match!');
            return false;
        }

        return true;

    } catch (error) {
        console.error('\n💥 Error:', error);
        return false;
    }
}

async function advancedExample() {
    console.log('\n\n🚀 MFKDF2 WASM Advanced Example');
    console.log('==================================');

    // Load WASM module
    const wasm = await loadWasm();
    const { setup_key, setup_password_factor, derive_key, DeriveFactorManager, MFKDFOptions } = wasm;

    try {
        // Create multiple password factors
        console.log('📝 Creating multiple factors...');
        const factor1 = setup_password_factor("password1", "pwd1");
        const factor2 = setup_password_factor("password2", "pwd2");

        console.log(`   Factor 1: ${factor1.id} (${factor1.entropy} bits)`);
        console.log(`   Factor 2: ${factor2.id} (${factor2.entropy} bits)`);

        // Set up 2-of-2 threshold
        const options = new MFKDFOptions();
        options.set_threshold(2);  // Both factors required
        options.set_id("advanced-key-001");

        console.log('\n🔑 Setting up 2-of-2 MFKDF2 key...');
        const setupKey = await setup_key([factor1, factor2], options);

        console.log(`   Key: ${Buffer.from(setupKey.key).toString('hex')}`);

        // Use factor manager for derivation
        console.log('\n🔓 Deriving key with factor manager...');
        const factorManager = new DeriveFactorManager();
        factorManager.add_password_factor("pwd1", "password1");
        factorManager.add_password_factor("pwd2", "password2");

        console.log(`   Active factors: ${factorManager.get_factor_ids().join(', ')}`);

        const derivedKey = await derive_key(setupKey.policy, factorManager);

        console.log(`   Derived Key: ${Buffer.from(derivedKey.key).toString('hex')}`);

        // Verify keys match
        const setupKeyHex = Buffer.from(setupKey.key).toString('hex');
        const derivedKeyHex = Buffer.from(derivedKey.key).toString('hex');

        if (setupKeyHex === derivedKeyHex) {
            console.log('\n✅ SUCCESS: Advanced example completed!');
        } else {
            console.log('\n❌ ERROR: Keys do not match in advanced example!');
            return false;
        }

        // Test partial derivation (should fail with 2-of-2)
        console.log('\n🧪 Testing partial derivation (should fail)...');
        const partialManager = new DeriveFactorManager();
        partialManager.add_password_factor("pwd1", "password1");
        // Only add one factor for 2-of-2 requirement

        try {
            await derive_key(setupKey.policy, partialManager);
            console.log('❌ ERROR: Partial derivation should have failed!');
            return false;
        } catch (error) {
            console.log('✅ SUCCESS: Partial derivation correctly failed');
        }

        return true;

    } catch (error) {
        console.error('\n💥 Advanced example error:', error);
        return false;
    }
}

async function main() {
    console.log('🎯 MFKDF2 WASM Binding Tests\n');

    const basicSuccess = await basicExample();
    const advancedSuccess = await advancedExample();

    console.log('\n📊 Results:');
    console.log(`   Basic Example: ${basicSuccess ? '✅ PASSED' : '❌ FAILED'}`);
    console.log(`   Advanced Example: ${advancedSuccess ? '✅ PASSED' : '❌ FAILED'}`);

    if (basicSuccess && advancedSuccess) {
        console.log('\n🎉 All tests passed! MFKDF2 WASM bindings are working correctly.');
    } else {
        console.log('\n💥 Some tests failed. Please check the implementation.');
        process.exit(1);
    }
}

// Run if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
}
