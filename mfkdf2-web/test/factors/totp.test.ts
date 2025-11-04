/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import speakeasy from 'speakeasy';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2.js';

suite('factors/totp', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('size', async () => {
    await mfkdf.setup.factors
      .totp({
        secret: Buffer.from('hello world')
      })
      .should.be.rejectedWith(Mfkdf2Error.InvalidSecretLength);
  });

  test('dynamic', async () => {
    const setup = await mfkdf.setup.key([await mfkdf.setup.factors.totp()]);

    // calculate code every time to ensure latest code usage
    let code = parseInt(
      speakeasy.totp({
        secret: Buffer.from(setup.outputs.totp.secret).toString('hex'),
        encoding: 'hex',
        step: setup.outputs.totp.period,
        algorithm: setup.outputs.totp.algorithm,
        digits: setup.outputs.totp.digits
      })
    );

    const derive1 = await mfkdf.derive.key(setup.policy, {
      totp: await mfkdf.derive.factors.totp(code)
    });

    code = parseInt(
      speakeasy.totp({
        secret: Buffer.from(setup.outputs.totp.secret).toString('hex'),
        encoding: 'hex',
        step: setup.outputs.totp.period,
        algorithm: setup.outputs.totp.algorithm,
        digits: setup.outputs.totp.digits
      })
    );

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      totp: await mfkdf.derive.factors.totp(code)
    });

    code = parseInt(
      speakeasy.totp({
        secret: Buffer.from(setup.outputs.totp.secret).toString('hex'),
        encoding: 'hex',
        step: setup.outputs.totp.period,
        algorithm: setup.outputs.totp.algorithm,
        digits: setup.outputs.totp.digits
      })
    );

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      totp: await mfkdf.derive.factors.totp(code)
    });

    derive1.key.toString('hex').should.equal(setup.key.toString('hex'));
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'));
    derive3.key.toString('hex').should.equal(setup.key.toString('hex'));
  });

  test('static', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.totp({
        secret: Buffer.from('abcdefghijklmnopqrst'),
        time: 1
      })
    ]);

    const derive1 = await mfkdf.derive.key(setup.policy, {
      totp: await mfkdf.derive.factors.totp(953265, { time: 1 })
    });

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      totp: await mfkdf.derive.factors.totp(241063, { time: 30001 })
    });

    const derive3 = await mfkdf.derive.key(derive1.policy, {
      totp: await mfkdf.derive.factors.totp(361687, { time: 60001 })
    });

    derive1.key.toString('hex').should.equal(setup.key.toString('hex'));
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'));
    derive3.key.toString('hex').should.equal(setup.key.toString('hex'));
  });

  test('defaults', async () => {
    await mfkdf.setup.key([await mfkdf.setup.factors.totp()]);
  });

  suite('errors', () => {
    /* invalid test - synchronous throw not supported in async context
    test('code/type', () => {
      (() => {
        mfkdf.derive.factors.totp('hello');
      }).should.throw(TypeError);
    });
    */

    test('code/window', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          time: 1650430806597
        })
      ]);

      await mfkdf.derive
        .key(setup.policy, {
          totp: await mfkdf.derive.factors.totp(953265, { time: 1750430943604 })
        })
        .should.be.rejectedWith(Mfkdf2Error.TotpWindowExceeded);
    });

    /* invalid test
    test('time/type', () => {
      (() => {
        mfkdf.derive.factors.totp(12345, { time: 'hello' });
      }).should.throw(TypeError);
    });
    */

    /* invalid test
    test('time/range', () => {
      (async () => {
        await mfkdf.derive.factors.totp(12345, { time: -1 });
      }).should.be.rejectedWith(RangeError);
    });
    */

    /* invalid test
    test('id/type', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst').buffer as ArrayBuffer,
          id: 12345
        })
        .should.be.rejectedWith(TypeError);
    });
    */

    test('id/range', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          id: ''
        })
        .should.be.rejectedWith(Mfkdf2Error.MissingFactorId);
    });

    /* invalid test
    test('digits/type', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst').buffer as ArrayBuffer,
          digits: 'hello'
        })
        .should.be.rejectedWith(TypeError);
    });
    */

    test('digits/low', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 4
        })
        .should.be.rejectedWith(Mfkdf2Error.InvalidTotpDigits);
    });

    test('digits/high', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 9
        })
        .should.be.rejectedWith(Mfkdf2Error.InvalidTotpDigits);
    });

    /* invalid test
    test('hash/range', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          hash: 'sha123'
        })
        .should.be.rejectedWith(RangeError);
    });
    */

    test('secret/type', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('hello')
        })
        .should.be.rejectedWith(Mfkdf2Error.InvalidSecretLength);
    });

    /* invalid test
    test('time/type', async () => {
      await mfkdf.setup.factors
        .totp({
          time: 'hello'
        })
        .should.be.rejectedWith(TypeError);
    });
    */

    /* invalid test
    test('time/range', async () => {
      await mfkdf.setup.factors
        .totp({
          time: -1
        })
        .should.be.rejectedWith(RangeError);
    });
    */

    /* invalid test
    test('step/type', async () => {
      await mfkdf.setup.factors
        .totp({
          step: 'hello'
        })
        .should.be.rejectedWith(TypeError);
    });
    */

    /* invalid test
    test('step/range', async () => {
      await mfkdf.setup.factors
        .totp({
          step: -1
        })
        .should.be.rejectedWith(RangeError);
    });
    */

    /* invalid test
    test('window/type', async () => {
      await mfkdf.setup.factors
        .totp({
          window: 'hello'
        })
        .should.be.rejectedWith(TypeError);
    });
    */

    /* invalid test
    test('window/range', async () => {
      await mfkdf.setup.factors
        .totp({
          window: -1
        })
        .should.be.rejectedWith(RangeError);
    });
    */
  });
});
