/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src';

suite('features/reconstitution', () => {
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
      { threshold: 3, integrity: false }
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
      .should.be.rejectedWith(Mfkdf2Error.ShareRecoveryError);

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
  });


  test('removeFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    const derive1 = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password2: await mfkdf.derive.factors.password('password2')
    })
    derive1.key.toString('hex').should.equal(key)

    await setup.removeFactor('password1')

    const derive2 = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    })
    derive2.key.toString('hex').should.equal(key)

    await mfkdf.derive
      .key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2')
      })
      .should.be.rejectedWith(Mfkdf2Error.ShareRecoveryError)

    await derive2.removeFactor('password2').should.be.rejectedWith(Mfkdf2Error.InvalidThreshold)

    await derive2.setThreshold(1)

    await derive2.removeFactor('password2')

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      password3: await mfkdf.derive.factors.password('password3')
    })
    derive3.key.toString('hex').should.equal(key)

    await mfkdf.derive
      .key(derive2.policy, {
        password2: await mfkdf.derive.factors.password('password2')
      })
      .should.be.rejectedWith(Mfkdf2Error.ShareRecoveryError)
  })

  test('removeFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    const derive1 = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password4: await mfkdf.derive.factors.password('password4')
    })
    derive1.key.toString('hex').should.equal(key)

    const derive2 = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    })
    derive2.key.toString('hex').should.equal(key)

    await setup.removeFactors(['password1', 'password4'])

    await mfkdf.derive
      .key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password4: await mfkdf.derive.factors.password('password4')
      })
      .should.be.rejectedWith(Mfkdf2Error.ShareRecoveryError)

    const derive3 = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    })
    derive3.key.toString('hex').should.equal(key)
  })

  test('addFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.addFactor(
      await mfkdf.setup.factors.password('password3', { id: 'password3' })
    )

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    })
    derive.key.toString('hex').should.equal(key)

  })

  test('addFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.addFactors([
      await mfkdf.setup.factors.password('password3', { id: 'password3' }),
      await mfkdf.setup.factors.password('password4', { id: 'password4' })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      password3: await mfkdf.derive.factors.password('password3'),
      password4: await mfkdf.derive.factors.password('password4')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('recoverFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.recoverFactor(
      await mfkdf.setup.factors.password('differentPassword3', {
        id: 'password3'
      })
    )

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password3: await mfkdf.derive.factors.password('differentPassword3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('recoverFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.recoverFactors([
      await mfkdf.setup.factors.password('differentPassword3', {
        id: 'password3'
      }),
      await mfkdf.setup.factors.password('otherPassword1', { id: 'password1' })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('otherPassword1'),
      password3: await mfkdf.derive.factors.password('differentPassword3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('reconstitute', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 3 }
    )
    const key = setup.key.toString('hex')

    await setup.reconstitute(
      ['password1'],
      [
        await mfkdf.setup.factors.password('otherPassword2', {
          id: 'password2'
        })
      ],
      2
    )

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('otherPassword2'),
      password3: await mfkdf.derive.factors.password('password3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('defaults', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.reconstitute()

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  suite('errors', () => {
    test('removeFactors/factor/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          ['password4'],
          [
            await mfkdf.setup.factors.password('otherPassword2', {
              id: 'password2'
            })
          ],
          2
        )
        .should.be.rejectedWith(Mfkdf2Error.MissingFactor)
    })

    test('removeFactors/factor/id/unique', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 2 }
      )

      await setup
        .reconstitute(
          ['password3'],
          [
            await mfkdf.setup.factors.password('otherPassword2', {
              id: 'password2'
            }),
            await mfkdf.setup.factors.password('diffPassword2', {
              id: 'password2'
            })
          ],
          2
        )
        .should.be.rejectedWith(Mfkdf2Error.DuplicateFactorId)
    })

    test('threshold/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup.reconstitute([], [], -1).should.be.rejectedWith(Mfkdf2Error.InvalidThreshold)
    })

    test('threshold/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup.reconstitute([], [], 4).should.be.rejectedWith(Mfkdf2Error.InvalidThreshold)
    })

    // TODO: type error tests are not added
  })
});
