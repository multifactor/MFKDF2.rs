/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf2, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src';
import mfkdf from 'mfkdf';
import { derivedKeyIsEqual } from './validation';

suite('differential/reconstitution', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('setThreshold', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ],
      { threshold: 3, integrity: false, id: 'key1' }
    );

    const keyHex = setup.key.toString('hex');

    await mfkdf.derive
      .key(
        setup.policy,
        {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2')
        },
        false
      )
      .should.be.rejectedWith(RangeError);

    await setup.setThreshold(2);

    const derive = await mfkdf.derive.key(
      setup.policy,
      {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2')
      },
      false
    );

    derive.key.toString('hex').should.equal(keyHex);

    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf2.setup.factors.password('password4', { id: 'password4' })
      ],
      { threshold: 3, integrity: false, id: 'key1' }
    );

    const keyHex2 = setup2.key.toString('hex');

    await mfkdf2.derive
      .key(
        setup2.policy,
        {
          password1: await mfkdf2.derive.factors.password('password1'),
          password2: await mfkdf2.derive.factors.password('password2')
        },
        false
      )
      .should.be.rejectedWith(Mfkdf2Error.ShareRecoveryError);

    await setup2.setThreshold(2);

    const derive2 = await mfkdf2.derive.key(
      setup2.policy,
      {
        password1: await mfkdf2.derive.factors.password('password1'),
        password2: await mfkdf2.derive.factors.password('password2')
      },
      false
    );

    derive2.key.toString('hex').should.equal(keyHex2);

    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(derive, derive2).should.be.true;
  });

  test('removeFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, id: 'key-removeFactor' }
    );

    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf2.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, id: 'key-removeFactor' }
    );

    const keyHex = setup.key.toString('hex');
    const keyHex2 = setup2.key.toString('hex');

    const derive1 = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password2: await mfkdf.derive.factors.password('password2')
    }, false);
    const derive2 = await mfkdf2.derive.key(setup2.policy, {
      password1: await mfkdf2.derive.factors.password('password1'),
      password2: await mfkdf2.derive.factors.password('password2')
    }, false);

    derive1.key.toString('hex').should.equal(keyHex);
    derive2.key.toString('hex').should.equal(keyHex2);

    await setup.removeFactor('password1');
    await setup2.removeFactor('password1');

    const derive3 = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    }, false);
    const derive4 = await mfkdf2.derive.key(setup2.policy, {
      password2: await mfkdf2.derive.factors.password('password2'),
      password3: await mfkdf2.derive.factors.password('password3')
    }, false);

    derive3.key.toString('hex').should.equal(keyHex);
    derive4.key.toString('hex').should.equal(keyHex2);

    // ensure parity across implementations
    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(derive1, derive2).should.be.true;
    derivedKeyIsEqual(derive3, derive4).should.be.true;
  });

  test('removeFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ],
      { threshold: 2, id: 'key-removeFactors' }
    );

    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf2.setup.factors.password('password4', { id: 'password4' })
      ],
      { threshold: 2, id: 'key-removeFactors' }
    );

    const keyHex = setup.key.toString('hex');
    const keyHex2 = setup2.key.toString('hex');

    const d1 = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password4: await mfkdf.derive.factors.password('password4')
    }, false);
    const d2 = await mfkdf2.derive.key(setup2.policy, {
      password1: await mfkdf2.derive.factors.password('password1'),
      password4: await mfkdf2.derive.factors.password('password4')
    }, false);
    d1.key.toString('hex').should.equal(keyHex);
    d2.key.toString('hex').should.equal(keyHex2);

    const d3 = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    }, false);
    const d4 = await mfkdf2.derive.key(setup2.policy, {
      password2: await mfkdf2.derive.factors.password('password2'),
      password3: await mfkdf2.derive.factors.password('password3')
    }, false);
    d3.key.toString('hex').should.equal(keyHex);
    d4.key.toString('hex').should.equal(keyHex2);

    await setup.removeFactors(['password1', 'password4']);
    await setup2.removeFactors(['password1', 'password4']);

    await mfkdf.derive
      .key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password4: await mfkdf.derive.factors.password('password4')
      })
      .should.be.rejected;
    await mfkdf2.derive
      .key(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password4: await mfkdf2.derive.factors.password('password4')
      })
      .should.be.rejectedWith(Mfkdf2Error.ShareRecoveryError);

    const d5 = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    });
    const d6 = await mfkdf2.derive.key(setup2.policy, {
      password2: await mfkdf2.derive.factors.password('password2'),
      password3: await mfkdf2.derive.factors.password('password3')
    });
    d5.key.toString('hex').should.equal(keyHex);
    d6.key.toString('hex').should.equal(keyHex2);

    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(d1, d2).should.be.true;
    derivedKeyIsEqual(d3, d4).should.be.true;
    derivedKeyIsEqual(d5, d6).should.be.true;
  });

  test('addFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2, id: 'key-addFactor' }
    );
    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2, id: 'key-addFactor' }
    );
    const key = setup.key.toString('hex');
    const key2 = setup2.key.toString('hex');

    await setup.addFactor(
      await mfkdf.setup.factors.password('password3', { id: 'password3' })
    );
    await setup2.addFactor(
      await mfkdf2.setup.factors.password('password3', { id: 'password3' })
    );

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    });
    const derive2 = await mfkdf2.derive.key(setup2.policy, {
      password2: await mfkdf2.derive.factors.password('password2'),
      password3: await mfkdf2.derive.factors.password('password3')
    });
    derive.key.toString('hex').should.equal(key);
    derive2.key.toString('hex').should.equal(key2);

    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(derive, derive2).should.be.true;
  });

  test('addFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2, id: 'key-addFactors' }
    );
    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2, id: 'key-addFactors' }
    );
    const key = setup.key.toString('hex');
    const key2 = setup2.key.toString('hex');

    await setup.addFactors([
      await mfkdf.setup.factors.password('password3', { id: 'password3' }),
      await mfkdf.setup.factors.password('password4', { id: 'password4' })
    ]);
    await setup2.addFactors([
      await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
      await mfkdf2.setup.factors.password('password4', { id: 'password4' })
    ]);

    const derive = await mfkdf.derive.key(setup.policy, {
      password3: await mfkdf.derive.factors.password('password3'),
      password4: await mfkdf.derive.factors.password('password4')
    });
    const derive2 = await mfkdf2.derive.key(setup2.policy, {
      password3: await mfkdf2.derive.factors.password('password3'),
      password4: await mfkdf2.derive.factors.password('password4')
    });
    derive.key.toString('hex').should.equal(key);
    derive2.key.toString('hex').should.equal(key2);

    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(derive, derive2).should.be.true;
  });

  test('recoverFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, id: 'key-recoverFactor' }
    );
    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf2.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, id: 'key-recoverFactor' }
    );
    const key = setup.key.toString('hex');
    const key2 = setup2.key.toString('hex');

    await setup.recoverFactor(
      await mfkdf.setup.factors.password('differentPassword3', { id: 'password3' })
    );
    await setup2.recoverFactor(
      await mfkdf2.setup.factors.password('differentPassword3', { id: 'password3' })
    );

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password3: await mfkdf.derive.factors.password('differentPassword3')
    });
    const derive2 = await mfkdf2.derive.key(setup2.policy, {
      password1: await mfkdf2.derive.factors.password('password1'),
      password3: await mfkdf2.derive.factors.password('differentPassword3')
    });
    derive.key.toString('hex').should.equal(key);
    derive2.key.toString('hex').should.equal(key2);

    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(derive, derive2).should.be.true;
  });

  test('recoverFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, id: 'key-recoverFactors' }
    );
    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf2.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, id: 'key-recoverFactors' }
    );
    const key = setup.key.toString('hex');
    const key2 = setup2.key.toString('hex');

    await setup.recoverFactors([
      await mfkdf.setup.factors.password('differentPassword3', { id: 'password3' }),
      await mfkdf.setup.factors.password('otherPassword1', { id: 'password1' })
    ]);
    await setup2.recoverFactors([
      await mfkdf2.setup.factors.password('differentPassword3', { id: 'password3' }),
      await mfkdf2.setup.factors.password('otherPassword1', { id: 'password1' })
    ]);

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('otherPassword1'),
      password3: await mfkdf.derive.factors.password('differentPassword3')
    });
    const derive2 = await mfkdf2.derive.key(setup2.policy, {
      password1: await mfkdf2.derive.factors.password('otherPassword1'),
      password3: await mfkdf2.derive.factors.password('differentPassword3')
    });
    derive.key.toString('hex').should.equal(key);
    derive2.key.toString('hex').should.equal(key2);

    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(derive, derive2).should.be.true;
  });

  test('reconstitute', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 3, id: 'key-reconstitute' }
    );
    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf2.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 3, id: 'key-reconstitute' }
    );
    const key = setup.key.toString('hex');
    const key2 = setup2.key.toString('hex');

    await setup.reconstitute(
      ['password1'],
      [await mfkdf.setup.factors.password('otherPassword2', { id: 'password2' })],
      2
    );
    await setup2.reconstitute(
      ['password1'],
      [await mfkdf2.setup.factors.password('otherPassword2', { id: 'password2' })],
      2
    );

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('otherPassword2'),
      password3: await mfkdf.derive.factors.password('password3')
    });
    const derive2 = await mfkdf2.derive.key(setup2.policy, {
      password2: await mfkdf2.derive.factors.password('otherPassword2'),
      password3: await mfkdf2.derive.factors.password('password3')
    });
    derive.key.toString('hex').should.equal(key);
    derive2.key.toString('hex').should.equal(key2);

    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(derive, derive2).should.be.true;
  });

  test('defaults', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, id: 'key-defaults' }
    );
    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf2.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, id: 'key-defaults' }
    );
    const key = setup.key.toString('hex');
    const key2 = setup2.key.toString('hex');

    await setup.reconstitute();
    await setup2.reconstitute();

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    });
    const derive2 = await mfkdf2.derive.key(setup2.policy, {
      password2: await mfkdf2.derive.factors.password('password2'),
      password3: await mfkdf2.derive.factors.password('password3')
    });
    derive.key.toString('hex').should.equal(key);
    derive2.key.toString('hex').should.equal(key2);

    derivedKeyIsEqual(setup, setup2).should.be.true;
    derivedKeyIsEqual(derive, derive2).should.be.true;
  });

  suite('errors', () => {
    test('removeFactors/factor/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3, id: 'key-errors-a' }
      );
      const setup2 = await mfkdf2.setup.key(
        [
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf2.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3, id: 'key-errors-a' }
      );

      await setup
        .reconstitute(
          ['password4'],
          [await mfkdf.setup.factors.password('otherPassword2', { id: 'password2' })],
          2
        )
        .should.be.rejected;

      await setup2
        .reconstitute(
          ['password4'],
          [await mfkdf2.setup.factors.password('otherPassword2', { id: 'password2' })],
          2
        )
        .should.be.rejectedWith(Mfkdf2Error.MissingFactor);
    });

    test('removeFactors/factor/id/unique', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 2, id: 'key-errors-b' }
      );
      const setup2 = await mfkdf2.setup.key(
        [
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf2.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 2, id: 'key-errors-b' }
      );

      await setup
        .reconstitute(
          ['password3'],
          [
            await mfkdf.setup.factors.password('otherPassword2', { id: 'password2' }),
            await mfkdf.setup.factors.password('diffPassword2', { id: 'password2' })
          ],
          2
        )
        .should.be.rejected;

      await setup2
        .reconstitute(
          ['password3'],
          [
            await mfkdf2.setup.factors.password('otherPassword2', { id: 'password2' }),
            await mfkdf2.setup.factors.password('diffPassword2', { id: 'password2' })
          ],
          2
        )
        .should.be.rejectedWith(Mfkdf2Error.DuplicateFactorId);
    });

    test('threshold/range/low', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3, id: 'key-errors-c' }
      );
      const setup2 = await mfkdf2.setup.key(
        [
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf2.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3, id: 'key-errors-c' }
      );

      await setup.reconstitute([], [], -1).should.be.rejected;
      await setup2.reconstitute([], [], -1).should.be.rejectedWith(Mfkdf2Error.InvalidThreshold);
    });

    test('threshold/range/high', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3, id: 'key-errors-d' }
      );
      const setup2 = await mfkdf2.setup.key(
        [
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf2.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3, id: 'key-errors-d' }
      );

      await setup.reconstitute([], [], 4).should.be.rejected;
      await setup2.reconstitute([], [], 4).should.be.rejectedWith(Mfkdf2Error.InvalidThreshold);
    });
  });
});