/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2.js';

suite('factors/stack', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  /* invalid test
  test('errors/id/type', async () => {
    mfkdf.setup.factors
      .stack(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        ],
        { id: 12345 }
      )
      .should.be.rejectedWith(TypeError);
  });
  */

  test('errors/id/range', async () => {
    mfkdf.setup.factors
      .stack(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        ],
        { id: '' }
      )
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId);
  });

  test('valid', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.stack(
          [
            await mfkdf.setup.factors.password('password1', {
              id: 'password1'
            }),
            await mfkdf.setup.factors.password('password2', {
              id: 'password2'
            })
          ],
          { id: 'stack1' }
        ),
        await mfkdf.setup.factors.stack(
          [
            await mfkdf.setup.factors.password('password3', {
              id: 'password3'
            }),
            await mfkdf.setup.factors.password('password4', {
              id: 'password4'
            })
          ],
          { id: 'stack2' }
        )
      ],
      { threshold: 1 }
    );

    // setup.policy.factors[0].params.should.not.have.property('hmac');
    setup.policy.factors[0].params.hmac.should.equal('');

    const derive1 = await mfkdf.derive.key(setup.policy, {
      stack1: await mfkdf.derive.factors.stack({
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2')
      })
    });

    const derive2 = await mfkdf.derive.key(setup.policy, {
      stack2: await mfkdf.derive.factors.stack({
        password3: await mfkdf.derive.factors.password('password3'),
        password4: await mfkdf.derive.factors.password('password4')
      })
    });

    derive1.key.toString('hex').should.equal(setup.key.toString('hex'));
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'));
  });
});
