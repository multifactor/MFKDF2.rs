/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';

suite('factors/uuid', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('valid', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.uuid({
          id: 'uuid1',
          uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
        }),
        await mfkdf.setup.factors.uuid({
          id: 'uuid2',
          uuid: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'
        }),
        await mfkdf.setup.factors.uuid({
          id: 'uuid3',
          uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b'
        })
      ],
      { threshold: 2 }
    );
    // Deep clone the policy as policy.$id and policy.$schema are deleted during unwrapping
    const setupPolicy = JSON.parse(JSON.stringify(setup.policy));

    const expectedOutputs = {
      uuid1: { uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' },
      uuid2: { uuid: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed' },
      uuid3: { uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b' }
    };
    setup.outputs.should.deep.equal(expectedOutputs);

    const derive1 = await mfkdf.derive.key(setup.policy, {
      uuid1: await mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'),
      uuid2: await mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed')
    });
    JSON.stringify(setupPolicy).should.equal(JSON.stringify(derive1.policy));

    const derive2 = await mfkdf.derive.key(setup.policy, {
      uuid2: await mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'),
      uuid3: await mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    });
    JSON.stringify(setupPolicy).should.equal(JSON.stringify(derive2.policy));

    const derive3 = await mfkdf.derive.key(setup.policy, {
      uuid1: await mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'),
      uuid3: await mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    });
    JSON.stringify(setupPolicy).should.equal(JSON.stringify(derive3.policy));

    const derive4 = await mfkdf.derive.key(setup.policy, {
      uuid1: await mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'),
      uuid2: await mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'),
      uuid3: await mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    });
    JSON.stringify(setupPolicy).should.equal(JSON.stringify(derive4.policy));

    setup.key.toString('hex').should.equal(derive1.key.toString('hex'));
    setup.key.toString('hex').should.equal(derive2.key.toString('hex'));
    setup.key.toString('hex').should.equal(derive3.key.toString('hex'));
    setup.key.toString('hex').should.equal(derive4.key.toString('hex'));

    JSON.stringify(setupPolicy).should.equal(JSON.stringify(derive1.policy));
    JSON.stringify(setupPolicy).should.equal(JSON.stringify(derive2.policy));
    JSON.stringify(setupPolicy).should.equal(JSON.stringify(derive3.policy));
    JSON.stringify(setupPolicy).should.equal(JSON.stringify(derive4.policy));
  });

  test('invalid', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.uuid({
          id: 'uuid1',
          uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
        }),
        await mfkdf.setup.factors.uuid({
          id: 'uuid2',
          uuid: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'
        }),
        await mfkdf.setup.factors.uuid({
          id: 'uuid3',
          uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b'
        })
      ],
      { threshold: 2 }
    );

    const derive1 = await mfkdf.derive.key(setup.policy, {
      uuid1: await mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6e'),
      uuid2: await mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed')
    },
      false
    );

    const derive2 = await mfkdf.derive.key(setup.policy, {
      uuid2: await mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'),
      uuid3: await mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0c')
    },
      false
    );

    const derive3 = await mfkdf.derive.key(setup.policy, {
      uuid1: await mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6b'),
      uuid3: await mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0d')
    },
      false
    );

    const derive4 = await mfkdf.derive.key(setup.policy, {
      uuid1: await mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-ab8dfbbd4bed'),
      uuid2: await mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-2b0d7b3dcb6d'),
      uuid3: await mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    },
      false
    );

    setup.key.toString('hex').should.not.equal(derive1.key.toString('hex'));
    setup.key.toString('hex').should.not.equal(derive2.key.toString('hex'));
    setup.key.toString('hex').should.not.equal(derive3.key.toString('hex'));
    setup.key.toString('hex').should.not.equal(derive4.key.toString('hex'));
  });
});
