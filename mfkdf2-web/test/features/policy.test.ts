/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2.js';

suite('policy', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  suite('validate', () => {
    test('valid', async () => {
      const policy = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      );

      (await mfkdf.policy.validate(policy.policy)).should.be.true;
    });

    test('invalid', async () => {
      await mfkdf.policy
        .setup(
          await mfkdf.policy.and(
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('password1', { id: 'password1' }),
              await mfkdf.setup.factors.password('password2', { id: 'password2' })
            ),
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('password3', { id: 'password1' }),
              await mfkdf.setup.factors.password('password4', { id: 'password2' })
            )
          )
        )
        .should.be.rejectedWith(Mfkdf2Error.DuplicateFactorId);
    });
  });

  suite('derive', async () => {
    test('all', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.all([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ])
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password3: await mfkdf.derive.factors.password('password3'),
        password4: await mfkdf.derive.factors.password('password4')
      });
      derive.key.toString('hex').should.equal(setup.key.toString('hex'));
    });

    test('any', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.any([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ])
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password3: await mfkdf.derive.factors.password('password3')
      });
      derive.key.toString('hex').should.equal(setup.key.toString('hex'));
    });

    test('atLeast', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.atLeast(3, [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ])
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password4: await mfkdf.derive.factors.password('password4')
      });
      derive.key.toString('hex').should.equal(setup.key.toString('hex'));
    });

    test('basic 1', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      );

      const derive1 = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password3: await mfkdf.derive.factors.password('password3')
      });
      derive1.key.toString('hex').should.equal(setup.key.toString('hex'));

      const derive2 = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password4: await mfkdf.derive.factors.password('password4')
      });
      derive2.key.toString('hex').should.equal(setup.key.toString('hex'));

      const derive3 = await mfkdf.policy.derive(setup.policy, {
        password2: await mfkdf.derive.factors.password('password2'),
        password3: await mfkdf.derive.factors.password('password3')
      });
      derive3.key.toString('hex').should.equal(setup.key.toString('hex'));

      const derive4 = await mfkdf.policy.derive(setup.policy, {
        password2: await mfkdf.derive.factors.password('password2'),
        password4: await mfkdf.derive.factors.password('password4')
      });
      derive4.key.toString('hex').should.equal(setup.key.toString('hex'));
    });

    test('basic 2', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.or(
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      );

      const derive1 = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2')
      });
      derive1.key.toString('hex').should.equal(setup.key.toString('hex'));

      const derive2 = await mfkdf.policy.derive(setup.policy, {
        password3: await mfkdf.derive.factors.password('password3'),
        password4: await mfkdf.derive.factors.password('password4')
      });
      derive2.key.toString('hex').should.equal(setup.key.toString('hex'));
    });

    test('deep', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.policy.and(
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('password2', { id: 'password2' }),
              await mfkdf.setup.factors.password('password3', { id: 'password3' })
            ),
            await mfkdf.policy.and(
              await mfkdf.setup.factors.password('password4', { id: 'password4' }),
              await mfkdf.policy.or(
                await mfkdf.setup.factors.password('password5', { id: 'password5' }),
                await mfkdf.setup.factors.password('password6', { id: 'password6' })
              )
            )
          )
        )
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password4: await mfkdf.derive.factors.password('password4'),
        password6: await mfkdf.derive.factors.password('password6')
      });
      derive.key.toString('hex').should.equal(setup.key.toString('hex'));
    });
  });

  suite('evaluate', () => {
    test('basic 1', async () => {
      const policy = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      );

      (await mfkdf.policy.evaluate(policy.policy, ['password1', 'password2'])).should.be.false;
      (await mfkdf.policy.evaluate(policy.policy, ['password3', 'password4'])).should.be.false;
      (await mfkdf.policy.evaluate(policy.policy, ['password1', 'password4'])).should.be.true;
      (await mfkdf.policy.evaluate(policy.policy, ['password2', 'password3'])).should.be.true;
    });

    test('basic 2', async () => {
      const policy = await mfkdf.policy.setup(
        await mfkdf.policy.or(
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      );

      (await mfkdf.policy.evaluate(policy.policy, ['password1', 'password2'])).should.be.true;
      (await mfkdf.policy.evaluate(policy.policy, ['password3', 'password4'])).should.be.true;
      (await mfkdf.policy.evaluate(policy.policy, ['password1', 'password4'])).should.be.false;
      (await mfkdf.policy.evaluate(policy.policy, ['password2', 'password3'])).should.be.false;
    });
  });

  suite('errors', () => {
    test('invalid policy', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.policy.and(
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('password1', { id: 'password1' }),
              await mfkdf.setup.factors.password('password2', { id: 'password2' })
            ),
            await mfkdf.policy.and(
              await mfkdf.setup.factors.password('password4', { id: 'password4' }),
              await mfkdf.policy.or(
                await mfkdf.setup.factors.password('password5', { id: 'password5' }),
                await mfkdf.setup.factors.password('password6', { id: 'password6' })
              )
            )
          )
        )
      ]);

      await mfkdf.policy
        .derive(setup.policy, {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2'),
          password4: await mfkdf.derive.factors.password('password4'),
          password6: await mfkdf.derive.factors.password('password6')
        })
        .should.be.rejectedWith(Mfkdf2Error.DuplicateFactorId);
    });

    test('invalid factors', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.policy.and(
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('password2', { id: 'password2' }),
              await mfkdf.setup.factors.password('password3', { id: 'password3' })
            ),
            await mfkdf.policy.and(
              await mfkdf.setup.factors.password('password4', { id: 'password4' }),
              await mfkdf.policy.or(
                await mfkdf.setup.factors.password('password5', { id: 'password5' }),
                await mfkdf.setup.factors.password('password6', { id: 'password6' })
              )
            )
          )
        )
      );

      await mfkdf.policy
        .derive(setup.policy, {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2'),
          password4: await mfkdf.derive.factors.password('password4')
        })
        .should.be.rejectedWith(Mfkdf2Error.InvalidThreshold);
    });
  });
});