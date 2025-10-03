/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/passkey', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('invalid/range - empty id', async () => {
    const secret = new Uint8Array(32)
    await mfkdf.setup.factors
      .passkey(secret.buffer, { id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('invalid/range - invalid secret length', async () => {
    const secret = new Uint8Array(16) // Wrong length
    await mfkdf.setup.factors
      .passkey(secret.buffer)
      .should.be.rejectedWith(Mfkdf2Error.InvalidHmacKey)
  })

  test('valid - with 32-byte secret', async () => {
    const secret = new Uint8Array(32)
    for (let i = 0; i < 32; i++) {
      secret[i] = i
    }
    const factor = await mfkdf.setup.factors.passkey(secret.buffer)
    factor.type.should.equal('passkey')
    factor.id.should.equal('passkey')
    factor.data.should.have.length(32)
    factor.entropy.should.equal(256)
  })

  test('valid - with id', async () => {
    const secret = new Uint8Array(32)
    const factor = await mfkdf.setup.factors.passkey(secret.buffer, { id: 'mykey' })
    factor.id.should.equal('mykey')
    factor.type.should.equal('passkey')
    const params = await factor.params()
    params.should.deep.equal({})
  })
})

