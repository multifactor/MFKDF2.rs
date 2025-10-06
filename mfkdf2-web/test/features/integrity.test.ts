/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2.js';

suite('integrity', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('disabled', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ])
    );

    // Tamper with policy
    setup.policy.factors[0].id = 'tampered';

    await mfkdf.policy.derive(
      setup.policy,
      {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password3: await mfkdf.derive.factors.password('password3'),
        password4: await mfkdf.derive.factors.password('password4')
      },
      false
    );
  });

  test('safety', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ]),
      { integrity: true }
    );

    const derive = await mfkdf.policy.derive(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3'),
      password4: await mfkdf.derive.factors.password('password4')
    });

    derive.key.toString('hex').should.equal(setup.key.toString('hex'));

    // Tamper with policy
    setup.policy.factors[0].id = 'tampered';

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2'),
          password3: await mfkdf.derive.factors.password('password3'),
          password4: await mfkdf.derive.factors.password('password4')
        },
        true
      )
      .should.be.rejectedWith(Mfkdf2Error.PolicyIntegrityCheckFailed);
  });

  test('liveness', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ]),
      { integrity: true }
    );

    const derive = await mfkdf.policy.derive(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password2: await mfkdf.derive.factors.password('password2'),
      password3: await mfkdf.derive.factors.password('password3'),
      password4: await mfkdf.derive.factors.password('password4')
    });

    derive.key.toString('hex').should.equal(setup.key.toString('hex'));

    await mfkdf.policy.derive(
      setup.policy,
      {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password3: await mfkdf.derive.factors.password('password3'),
        password4: await mfkdf.derive.factors.password('password4')
      },
      true
    );
  });

  test('$id', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ]),
      { integrity: true }
    );

    // Tamper with policy
    setup.policy.$id = 'tampered';

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2')
        },
        true
      )
      .should.be.rejectedWith(Mfkdf2Error.PolicyIntegrityCheckFailed);
  });

  test('threshold', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ]),
      { integrity: true }
    );

    // Tamper with policy - threshold validation happens before integrity check
    setup.policy.threshold += 1;

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2')
        },
        true
      )
      .should.be.rejectedWith(Mfkdf2Error.InvalidThreshold);
  });

  test('salt', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ]),
      { integrity: true }
    );

    // Tamper with policy
    setup.policy.salt = 'Ny9+L9LQHOKh1x3Acqy7pMb9JaEIfNfxU/TsDON+Ht4=';

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2')
        },
        true
      )
      .should.be.rejectedWith(Mfkdf2Error.PolicyIntegrityCheckFailed);
  });

  test('factor/id', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ]),
      { integrity: true }
    );

    // Tamper with policy
    setup.policy.factors[0].id = 'tampered';

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2')
        },
        true
      )
      .should.be.rejectedWith(Mfkdf2Error.PolicyIntegrityCheckFailed);
  });

  test('derive', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ]),
      { integrity: true }
    );

    const derive = await mfkdf.policy.derive(
      setup.policy,
      {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2'),
        password3: await mfkdf.derive.factors.password('password3'),
        password4: await mfkdf.derive.factors.password('password4')
      },
      true
    );

    derive.key.toString('hex').should.equal(setup.key.toString('hex'));

    // Tamper with policy
    derive.policy.factors[0].id = 'tampered';

    await mfkdf.policy
      .derive(
        derive.policy,
        {
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2'),
          password3: await mfkdf.derive.factors.password('password3'),
          password4: await mfkdf.derive.factors.password('password4')
        },
        true
      )
      .should.be.rejectedWith(Mfkdf2Error.PolicyIntegrityCheckFailed);
  });

  test.skip('reconstitution', async () => {
    // TODO (@lonerapier): recoverFactor functionality not yet implemented
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, integrity: true }
    );
    const key = setup.key.toString('hex');

    await setup.recoverFactor(
      await mfkdf.setup.factors.password('differentPassword3', {
        id: 'password3'
      })
    );

    const derive = await mfkdf.derive.key(
      setup.policy,
      {
        password1: await mfkdf.derive.factors.password('password1'),
        password3: await mfkdf.derive.factors.password('differentPassword3')
      },
      true
    );
    derive.key.toString('hex').should.equal(key);
  });
});

