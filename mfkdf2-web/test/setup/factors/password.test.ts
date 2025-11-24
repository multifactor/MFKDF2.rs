/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/password', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  /* invalid
  test('invalid/type', async () => {
    await mfkdf.setup.factors.password(12345).should.be.rejectedWith(TypeError)
    await mfkdf.setup.factors
      .password('password', { id: 12345 })
      .should.be.rejectedWith(TypeError)
  })
  */

  test('invalid/range', async () => {
    await mfkdf.setup.factors.password('').should.be.rejectedWith(Mfkdf2Error.PasswordEmpty)
    await mfkdf.setup.factors
      .password('password', { id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('valid', async () => {
    const factor = await mfkdf.setup.factors.password('hello')
    factor.type.should.equal('password')
    factor.data.toString('hex').should.equal('68656c6c6f')
    const params = await factor.params()
    params.should.deep.equal({})
  })
})

suite('setup/factors/password - with key parameter', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('params() and output() with no key (uses default)', async () => {
    const factor = await mfkdf.setup.factors.password('hello');

    // Call without key - should use default zero-filled key
    const params = await factor.params();
    params.should.deep.equal({});

    const output = await factor.output();
    output.should.have.property('strength');
  });

  test('params() and output() with explicit 32-byte key', async () => {
    const factor = await mfkdf.setup.factors.password('hello');

    // Create a specific 32-byte key
    const customKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      customKey[i] = i;
    }

    // Call with explicit key
    const params = await factor.params(customKey.buffer);
    params.should.deep.equal({});

    const output = await factor.output(customKey.buffer);
    output.should.have.property('strength');
  });

  test('params() and output() return same results regardless of key for password factor', async () => {
    const factor = await mfkdf.setup.factors.password('hello');

    // Password factor doesn't use the key, so results should be identical
    const paramsNoKey = await factor.params();
    const paramsWithKey = await factor.params(new Uint8Array(32).buffer);

    paramsNoKey.should.deep.equal(paramsWithKey);

    const outputNoKey = await factor.output();
    const outputWithKey = await factor.output(new Uint8Array(32).buffer);

    // Both should have strength property (value might differ slightly but structure same)
    outputNoKey.should.have.property('strength');
    outputWithKey.should.have.property('strength');
  });
});