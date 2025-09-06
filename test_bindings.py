#!/usr/bin/env python3

import sys
import os
import asyncio
import json

# Add the out directory to the path so we can import mfkdf2
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'out'))

try:
    import mfkdf2
    print("✅ Successfully imported mfkdf2 module!")
    print(f"Available items: {[attr for attr in dir(mfkdf2) if not attr.startswith('_')]}")
except ImportError as e:
    print(f"❌ Failed to import mfkdf2: {e}")
    sys.exit(1)

async def test_basic_functionality():
    """Test basic MFKDF2 functionality using password factor like Rust integration test"""
    print("\n🧪 Testing basic MFKDF2 functionality...")
    
    try:
        # Create a password factor (similar to the Rust integration test)
        print("Creating password factor...")
        password_options = mfkdf2.PasswordOptions(id="password_1")
        password_factor = mfkdf2.setup_factors_password("Tr0ubd4dour", password_options)
        
        print("✅ Successfully created password factor")
        print(f"   Factor ID: {password_factor.id}")
        print(f"   Factor Kind: {password_factor.kind}")
        print(f"   Data length: {len(password_factor.data)} bytes")
        print(f"   Salt length: {len(password_factor.salt)} bytes")
        print(f"   Entropy: {password_factor.entropy} bits")
        
        # Create options (using defaults like the Rust test)
        options = mfkdf2.Mfkdf2Options(
            id=None,      # Let it generate
            threshold=None,  # Default to 1 of 1
            salt=None     # Let it generate a random salt
        )
        print("✅ Successfully created MFKDF2Options")
        
        # Test the key derivation function (setup phase)
        print("\n🔑 Testing key setup...")
        derived_key = await mfkdf2.setup_key([password_factor], options)
        print("✅ Successfully set up key!")
        print(f"   Key type: {type(derived_key)}")
        
        # Try to access some properties (if they exist)
        try:
            print(f"   Derived key object: {derived_key}")
        except Exception as e:
            print(f"   Note: Cannot display key details: {e}")
            
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Main test function"""
    print("🚀 Starting MFKDF2 Python bindings test...")
    
    success = await test_basic_functionality()
    
    if success:
        print("\n🎉 All tests passed! The Python bindings are working correctly.")
    else:
        print("\n💥 Some tests failed. Check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
