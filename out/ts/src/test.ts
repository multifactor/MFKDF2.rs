import { uniffiInitAsync } from './index.web.js';
import mfkdf2, { type Policy } from './index.js';

async function main() {
  console.log('🧪 Starting UniFFI WASM init...');
  await uniffiInitAsync();
  console.log('✅ UniFFI initialized');

  console.log('📝 Creating setup password factor...');
  const factor = mfkdf2.setup.factors.password('Tr0ubd4dour', { id: 'password_1' });
  console.log('✅ Setup factor created:', { id: factor.id, kind: (factor as any).kind });

  console.log('🔑 Creating key with setup factors...');
  const derived = await mfkdf2.setup.key([factor]);
  console.log('✅ Key created. Policy ID:', derived.policy.id);

  console.log('📝 Creating derive password factor...');
  const deriveFactor = mfkdf2.derive.factors.password('Tr0ubd4dour');
  const factors = new Map<string, any>([[factor.id!, deriveFactor]]);
  console.log('✅ Derive factors prepared with keys:', Array.from(factors.keys()));

  console.log('🔓 Deriving key from policy and factors...');
  const derived2 = await mfkdf2.derive.key(derived.policy as Policy, factors);
  console.log('✅ Key derived');

  const k1 = Buffer.from(derived.key).toString('hex');
  const k2 = Buffer.from(derived2.key).toString('hex');
  const match = k1 === k2;
  console.log('🔬 Key1:', k1);
  console.log('🔬 Key2:', k2);
  console.log('🎯 Keys match:', match);
  if (!match) process.exit(1);
}

main().catch((e) => {
  console.error('❌ Test failed:', e);
  process.exit(1);
});
