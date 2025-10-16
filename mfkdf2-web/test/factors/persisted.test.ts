/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';

suite('persistence', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('valid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.hotp(),
      await mfkdf.setup.factors.password('password')
    ])

    const hotp = await setup.persistFactor('hotp')

    const derive = await mfkdf.derive.key(setup.policy, {
      hotp: await mfkdf.derive.factors.persisted(hotp),
      password: await mfkdf.derive.factors.password('password')
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))
  })
});