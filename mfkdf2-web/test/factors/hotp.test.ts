/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2.js';

suite('factors/hotp', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('size', async () => {
    await mfkdf.setup.factors
      .hotp({
        secret: Buffer.from('hello world').buffer as ArrayBuffer
      })
      .should.be.rejectedWith('Mfkdf2Error.InvalidSecretLength');
  });

  test('valid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.hotp({
        secret: Buffer.from('abcdefghijklmnopqrst'),
      })
    ]);

    const derive1 = await mfkdf.derive.key(setup.policy, {
      hotp: await mfkdf.derive.factors.hotp(241063)
    });

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      hotp: await mfkdf.derive.factors.hotp(361687)
    });

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      hotp: await mfkdf.derive.factors.hotp(979122)
    });

    setup.key.toString('hex').should.equal(derive1.key.toString('hex'));
    derive1.key.toString('hex').should.equal(derive2.key.toString('hex'));
    derive2.key.toString('hex').should.equal(derive3.key.toString('hex'));
  });

  test('defaults', async () => {
    await mfkdf.setup.key([await mfkdf.setup.factors.hotp()]);
  });

  suite('errors', () => {
    /* invalid test 
    test('code/type', () => {
      (() => {
        mfkdf.derive.factors.hotp('hello');
      }).should.throw(TypeError);
    });
    */

    /* invalid test 
    test('id/type', async () => {
      await mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          id: 12345
        })
        .should.be.rejectedWith(TypeError);
    });
    */

    test('id/range', async () => {
      await mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          id: ''
        })
        .should.be.rejectedWith(Mfkdf2Error.MissingFactorId);
    });

    /* invalid test 
    test('digits/type', async () => {
      await mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 'hello'
        })
        .should.be.rejectedWith(TypeError);
    });
    */

    test('digits/low', async () => {
      await mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 4
        })
        .should.be.rejectedWith(Mfkdf2Error.InvalidHotpDigits);
    });

    test('digits/high', async () => {
      await mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 9
        })
        .should.be.rejectedWith(Mfkdf2Error.InvalidHotpDigits);
    });

    /* invalid test 
    test('hash/range', async () => {
      await mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          hash: 'sha123'
        })
        .should.be.rejectedWith(RangeError);
    });
    */

    test('secret/type', async () => {
      await mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('hello')
        })
        .should.be.rejectedWith(Mfkdf2Error.InvalidSecretLength);
    });
  });
});
