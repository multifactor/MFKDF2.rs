import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf from '../src/api';

suite('mfkdf2 bindings', () => {
  test('setup and derive matching keys', async () => {
    // Initialize UniFFI if needed
    const { uniffiInitAsync } = await import('../src/index.web.js');
    await uniffiInitAsync();

    console.log('Starting UniFFI WASM init...');
    console.log('UniFFI initialized');

    console.log('Creating setup password factor...');
    const factor = await mfkdf.setup.factors.password('Tr0ubd4dour', { id: 'password_1' });
    console.log('Setup factor created:', { id: factor.id, type: factor.type });
    factor.should.have.property('id');
    factor.should.have.property('type', 'password');

    console.log('Creating key with setup factors...');
    const derived = await mfkdf.setup.key([factor]);
    console.log('Key created. Policy ID:', derived.policy.id);
    derived.should.have.property('policy');
    derived.policy.should.have.property('id');
    derived.should.have.property('key');

    console.log('Creating derive password factor...');
    const deriveFactor = mfkdf.derive.factors.password('Tr0ubd4dour');
    const factors = new Map([[factor.id, deriveFactor]]);
    console.log('Derive factors prepared with keys:', Array.from(factors.keys()));
    factors.should.be.an('Map');
    factors.should.have.property('size', 1);

    console.log('Deriving key from policy and factors...');
    const derived2 = await mfkdf.derive.key(derived.policy, factors);
    console.log('Key derived');
    derived2.should.have.property('key');

    const k1 = Buffer.from(derived.key).toString('hex');
    const k2 = Buffer.from(derived2.key).toString('hex');
    const match = k1 === k2;
    console.log('Key1:', k1);
    console.log('Key2:', k2);
    console.log('Keys match:', match);

    // Mocha assertion instead of process.exit
    k1.should.equal(k2);
  });
});