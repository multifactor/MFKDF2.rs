/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import { mfkdf as mfkdf2, uniffiInitAsync, initRustLogging, LogLevel } from '../../src/api';
import { Mfkdf2Error } from '../../src';
import { derivedKeyIsEqual } from './validation';

import mfkdf from 'mfkdf';

// each factor individually and single
// each factor inidividually and multiple
// factor combinations with full threshold
// factor combinations with partial threshold
// stack factors
// reconstitution

suite('differential/derive', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
    // await initRustLogging(LogLevel.Debug);
  });

  suite('single factor', () => {
    test('password', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.password('password1', { id: 'password1' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1')
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })
  });

  suite('multiple factors', () => {
    test('password', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password2: await mfkdf2.derive.factors.password('password2')
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })
  });

  suite('factor threshold', () => {
    test('password', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ], { threshold: 2, id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        password2: await mfkdf.derive.factors.password('password2')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf2.setup.factors.password('password3', { id: 'password3' })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        password2: await mfkdf2.derive.factors.password('password2'),
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })
  });

  suite('factor combinations', () => { })

  suite('stack factors', () => { })

  suite('reconstitution', () => { })
});