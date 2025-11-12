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

suite('differential/hints', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('getHint', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', {
        id: 'password1'
      })
    ])
    const hint = await setup.getHint('password1', 7)

    const setup2 = await mfkdf2.setup.key([
      await mfkdf2.setup.factors.password('password1', {
        id: 'password1'
      })
    ])

    const hint2 = await setup2.getHint('password1', 7)

    hint.should.be.a('string')
    hint.length.should.equal(7)
    hint2.should.equal(hint)

    const hinta = await setup.getHint('password1', 24)
    hinta.should.be.a('string')
    hinta.length.should.equal(24)

    const hinta2 = await setup2.getHint('password1', 24)
    hinta2.should.equal(hinta)

    const derived = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1')
    })

    const derived2 = await mfkdf2.derive.key(setup2.policy, {
      password1: await mfkdf2.derive.factors.password('password1')
    })
    derived.key.toString('hex').should.equal(setup.key.toString('hex'))

    const hint3 = await derived.getHint('password1', 7)
    hint3.should.equal(hint)

    const hinta3 = await derived.getHint('password1', 24)
    hinta3.should.equal(hinta)

    const hint4 = await derived2.getHint('password1', 7)
    hint4.should.equal(hint)

    const hinta4 = await derived2.getHint('password1', 24)
    hinta4.should.equal(hinta)

    const derived3 = await mfkdf.derive.key(
      setup.policy,
      {
        password1: await mfkdf.derive.factors.password('wrongpassword')
      },
      false
    )

    const derived4 = await mfkdf2.derive.key(
      setup2.policy,
      {
        password1: await mfkdf2.derive.factors.password('wrongpassword')
      },
      false
    )

    const hinta5 = await derived3.getHint('password1', 24)
    hinta5.should.not.equal(hinta)

    const hinta6 = await derived4.getHint('password1', 24)
    hinta6.should.not.equal(hinta)
  })

  test('addHint', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ],
      { id: 'key1' }
    )

    const setup2 = await mfkdf2.setup.key(
      [
        await mfkdf2.setup.factors.password('password1', { id: 'password1' })
      ],
      { id: 'key1' }
    )

    await setup.addHint('password1')
    await setup2.addHint('password1')

    setup.policy.factors[0].hint.should.be.a('string')
    setup.policy.factors[0].hint.length.should.equal(7)
    setup2.policy.factors[0].hint.should.be.a('string')
    setup2.policy.factors[0].hint.length.should.equal(7)

    await setup.addHint('password1', 24)
    await setup2.addHint('password1', 24)

    setup.policy.factors[0].hint.should.be.a('string')
    setup.policy.factors[0].hint.length.should.equal(24)
    setup2.policy.factors[0].hint.should.be.a('string')
    setup2.policy.factors[0].hint.length.should.equal(24)

    const derived = await mfkdf.derive.key(
      setup.policy,
      {
        password1: await mfkdf.derive.factors.password('password1')
      },
      false
    )
    const derived2 = await mfkdf2.derive.key(
      setup2.policy,
      {
        password1: await mfkdf2.derive.factors.password('password1')
      },
      false
    )

    derivedKeyIsEqual(derived, derived2).should.be.true
  })
});