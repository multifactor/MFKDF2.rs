/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2';

suite('factors/question', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('valid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.question(' Fido-', {
        question: 'What is the name of your first pet?'
      })
    ]);

    const derive = await mfkdf.derive.key(setup.policy, {
      question: await mfkdf.derive.factors.question('-f_i%d#o ? ') // Changed: await the derive factor
    });

    setup.key.toString('hex').should.equal(derive.key.toString('hex'));
    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive.policy));
  });

  test('invalid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.question('Fido', {
        question: 'What is the name of your first pet?'
      })
    ]);

    const derive = await mfkdf.derive.key(
      setup.policy,
      {
        question: await mfkdf.derive.factors.question('Rex') // Changed: await the derive factor
      },
      false
    );

    setup.key.toString('hex').should.not.equal(derive.key.toString('hex'));
  });

  suite('errors', () => {
    test('derive', async () => {
      // invalid
      // (async () => {
      //   await mfkdf.derive.factors.question(123);
      // }).should.throw(TypeError);

      await mfkdf.derive.factors.question('').should.be.rejectedWith(Mfkdf2Error.AnswerEmpty);
    });

    test('setup', async () => {
      // invalid
      // await mfkdf.setup.factors
      //   .question(12345)
      //   .should.be.rejectedWith(TypeError);
      await mfkdf.setup.factors.question('').should.be.rejectedWith(Mfkdf2Error.AnswerEmpty);
      // await mfkdf.setup.factors
      //   .question('hello', { id: 12345 })
      //   .should.be.rejectedWith(TypeError);
      await mfkdf.setup.factors
        .question('hello', { id: '' })
        .should.be.rejectedWith(Mfkdf2Error.MissingFactorId);
      // await mfkdf.setup.factors
      //   .question('hello', { question: 12345 })
      //   .should.be.rejectedWith(TypeError);
    });
  });
});
