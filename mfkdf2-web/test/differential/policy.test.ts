/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf2, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2.js';
import mfkdf from 'mfkdf';
import { derivedKeyIsEqual } from './validation';

suite('differential/policy', () => {
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
        ),
        { id: 'policy1' }
      );

      (await mfkdf.policy.validate(policy.policy)).should.be.true;

      const policy2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.and(
          await mfkdf2.policy.or(
            await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf2.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf2.policy.or(
            await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf2.setup.factors.password('password4', { id: 'password4' })
          )
        ),
        { id: 'policy1' }
      );

      (await mfkdf2.policy.validate(policy2.policy)).should.be.true;

      derivedKeyIsEqual(policy, policy2).should.be.true;
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
        ]),
        { id: 'policy1' }
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password3: await mfkdf.derive.factors.password('password3'),
        password4: await mfkdf.derive.factors.password('password4')
      });
      derive.key.toString('hex').should.equal(setup.key.toString('hex'));

      const setup2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.all([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf2.setup.factors.password('password4', { id: 'password4' })
        ]),
        { id: 'policy1' }
      );

      const derive2 = await mfkdf2.policy.derive(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password2: await mfkdf2.derive.factors.password('password2'),
        password3: await mfkdf2.derive.factors.password('password3'),
        password4: await mfkdf2.derive.factors.password('password4')
      });

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'));
      derivedKeyIsEqual(setup, setup2).should.be.true;
      derivedKeyIsEqual(derive, derive2).should.be.true;
    });

    test('any', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.any([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ]),
        { id: 'policy1' }
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password3: await mfkdf.derive.factors.password('password3')
      });
      derive.key.toString('hex').should.equal(setup.key.toString('hex'));

      const setup2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.any([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf2.setup.factors.password('password4', { id: 'password4' })
        ]),
        { id: 'policy1' }
      );

      const derive2 = await mfkdf2.policy.derive(setup2.policy, {
        password3: await mfkdf2.derive.factors.password('password3')
      });
      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'));
      derivedKeyIsEqual(setup, setup2).should.be.true;
      derivedKeyIsEqual(derive, derive2).should.be.true;
    });

    test('atLeast', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.atLeast(3, [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ]),
        { id: 'policy1' }
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password4: await mfkdf.derive.factors.password('password4')
      });
      derive.key.toString('hex').should.equal(setup.key.toString('hex'));

      const setup2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.atLeast(3, [
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf2.setup.factors.password('password4', { id: 'password4' })
        ]),
        { id: 'policy1' }
      );

      const derive2 = await mfkdf2.policy.derive(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password2: await mfkdf2.derive.factors.password('password2'),
        password4: await mfkdf2.derive.factors.password('password4')
      });
      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'));
      derivedKeyIsEqual(setup, setup2).should.be.true;
      derivedKeyIsEqual(derive, derive2).should.be.true;
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
        ),
        { id: 'policy1' }
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

      const setup2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.and(
          await mfkdf2.policy.or(
            await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf2.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf2.policy.or(
            await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf2.setup.factors.password('password4', { id: 'password4' })
          )
        ),
        { id: 'policy1' }
      );

      const derive12 = await mfkdf2.policy.derive(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password3: await mfkdf2.derive.factors.password('password3')
      });
      derive12.key.toString('hex').should.equal(setup2.key.toString('hex'));

      const derive22 = await mfkdf2.policy.derive(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password4: await mfkdf2.derive.factors.password('password4')
      });
      derive22.key.toString('hex').should.equal(setup2.key.toString('hex'));

      const derive32 = await mfkdf2.policy.derive(setup2.policy, {
        password2: await mfkdf2.derive.factors.password('password2'),
        password3: await mfkdf2.derive.factors.password('password3')
      });
      derive32.key.toString('hex').should.equal(setup2.key.toString('hex'));

      const derive42 = await mfkdf2.policy.derive(setup2.policy, {
        password2: await mfkdf2.derive.factors.password('password2'),
        password4: await mfkdf2.derive.factors.password('password4')
      });
      derive42.key.toString('hex').should.equal(setup2.key.toString('hex'));

      derivedKeyIsEqual(setup, setup2).should.be.true;
      derivedKeyIsEqual(derive1, derive12).should.be.true;
      derivedKeyIsEqual(derive2, derive22).should.be.true;
      derivedKeyIsEqual(derive3, derive32).should.be.true;
      derivedKeyIsEqual(derive4, derive42).should.be.true;
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
        ),
        { id: 'policy1' }
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

      const setup2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.or(
          await mfkdf2.policy.and(
            await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf2.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf2.policy.and(
            await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf2.setup.factors.password('password4', { id: 'password4' })
          )
        ),
        { id: 'policy1' }
      );

      const derive12 = await mfkdf2.policy.derive(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password2: await mfkdf2.derive.factors.password('password2')
      });
      derive12.key.toString('hex').should.equal(setup2.key.toString('hex'));

      const derive22 = await mfkdf2.policy.derive(setup2.policy, {
        password3: await mfkdf2.derive.factors.password('password3'),
        password4: await mfkdf2.derive.factors.password('password4')
      });
      derive22.key.toString('hex').should.equal(setup2.key.toString('hex'));

      derivedKeyIsEqual(setup, setup2).should.be.true;
      derivedKeyIsEqual(derive1, derive12).should.be.true;
      derivedKeyIsEqual(derive2, derive22).should.be.true;
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
        ),
        { id: 'policy1' }
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password4: await mfkdf.derive.factors.password('password4'),
        password6: await mfkdf.derive.factors.password('password6')
      });
      derive.key.toString('hex').should.equal(setup.key.toString('hex'));

      const setup2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.and(
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.policy.and(
            await mfkdf2.policy.or(
              await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
              await mfkdf2.setup.factors.password('password3', { id: 'password3' })
            ),
            await mfkdf2.policy.and(
              await mfkdf2.setup.factors.password('password4', { id: 'password4' }),
              await mfkdf2.policy.or(
                await mfkdf2.setup.factors.password('password5', { id: 'password5' }),
                await mfkdf2.setup.factors.password('password6', { id: 'password6' })
              )
            )
          )
        ),
        { id: 'policy1' }
      );

      const derive2 = await mfkdf2.policy.derive(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password2: await mfkdf2.derive.factors.password('password2'),
        password4: await mfkdf2.derive.factors.password('password4'),
        password6: await mfkdf2.derive.factors.password('password6')
      });
      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'));

      derivedKeyIsEqual(setup, setup2).should.be.true;
      derivedKeyIsEqual(derive, derive2).should.be.true;
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
        ),
        { id: 'policy1' }
      );

      (await mfkdf.policy.evaluate(policy.policy, ['password1', 'password2'])).should.be.false;
      (await mfkdf.policy.evaluate(policy.policy, ['password3', 'password4'])).should.be.false;
      (await mfkdf.policy.evaluate(policy.policy, ['password1', 'password4'])).should.be.true;
      (await mfkdf.policy.evaluate(policy.policy, ['password2', 'password3'])).should.be.true;

      const policy2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.and(
          await mfkdf2.policy.or(
            await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf2.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf2.policy.or(
            await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf2.setup.factors.password('password4', { id: 'password4' })
          )
        ),
        { id: 'policy1' }
      );

      (await mfkdf2.policy.evaluate(policy2.policy, ['password1', 'password2'])).should.be.false;
      (await mfkdf2.policy.evaluate(policy2.policy, ['password3', 'password4'])).should.be.false;
      (await mfkdf2.policy.evaluate(policy2.policy, ['password1', 'password4'])).should.be.true;
      (await mfkdf2.policy.evaluate(policy2.policy, ['password2', 'password3'])).should.be.true;

      derivedKeyIsEqual(policy, policy2).should.be.true;
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
        ),
        { id: 'policy1' }
      );

      (await mfkdf.policy.evaluate(policy.policy, ['password1', 'password2'])).should.be.true;
      (await mfkdf.policy.evaluate(policy.policy, ['password3', 'password4'])).should.be.true;
      (await mfkdf.policy.evaluate(policy.policy, ['password1', 'password4'])).should.be.false;
      (await mfkdf.policy.evaluate(policy.policy, ['password2', 'password3'])).should.be.false;

      const policy2 = await mfkdf2.policy.setup(
        await mfkdf2.policy.or(
          await mfkdf2.policy.and(
            await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf2.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf2.policy.and(
            await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf2.setup.factors.password('password4', { id: 'password4' })
          )
        ),
        { id: 'policy1' }
      );

      (await mfkdf2.policy.evaluate(policy2.policy, ['password1', 'password2'])).should.be.true;
      (await mfkdf2.policy.evaluate(policy2.policy, ['password3', 'password4'])).should.be.true;
      (await mfkdf2.policy.evaluate(policy2.policy, ['password1', 'password4'])).should.be.false;
      (await mfkdf2.policy.evaluate(policy2.policy, ['password2', 'password3'])).should.be.false;

      derivedKeyIsEqual(policy, policy2).should.be.true;
    });
  });
});