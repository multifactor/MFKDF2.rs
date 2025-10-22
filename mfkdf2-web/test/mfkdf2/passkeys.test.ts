/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import crypto from 'crypto';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2';

suite('mfkdf2/passkeys', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('liveness', async () => {
    const prf = await crypto.randomBytes(32)

    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.passkey(prf)
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      passkey: await mfkdf.derive.factors.passkey(prf)
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  test('safety', async () => {
    const prf = await crypto.randomBytes(32)

    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.passkey(prf)
    ])

    const prf2 = await crypto.randomBytes(32)

    const derive = await mfkdf.derive.key(
      setup.policy,
      {
        passkey: await mfkdf.derive.factors.passkey(prf2)
      },
      false
    )

    derive.key.toString('hex').should.not.equal(setup.key.toString('hex'))
  })

  test('coverage', async () => {
    /* invalid test
    await mfkdf.setup.factors
      .passkey('hello')
      .should.be.rejectedWith(TypeError)

    await mfkdf.setup.factors
      .passkey(crypto.randomBytes(32), { id: 123 })
      .should.be.rejectedWith(TypeError)
    */

    await mfkdf.setup.factors
      .passkey(crypto.randomBytes(32), { id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)

    /* invalid test
    await mfkdf.setup.factors
      .passkey(Buffer.from('hello'))
      .should.be.rejectedWith(RangeError);

    (() => {
      mfkdf.derive.factors.passkey('hello')
    }).should.throw(TypeError);

    (() => {
      mfkdf.derive.factors.passkey(Buffer.from('hello'))
    }).should.throw(RangeError)
    */
  })
});