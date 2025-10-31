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
import speakeasy from 'speakeasy';

// each factor individually and single
// each factor inidividually and multiple
// factor combinations with full threshold
// factor combinations with partial threshold
// stack factors
// reconstitution
// factor outputs match

suite('differential/derive', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
    await initRustLogging(LogLevel.Debug);
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

    test('uuid', async () => {
      const uuid = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        uuid1: await mfkdf.derive.factors.uuid(uuid)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.uuid({ id: 'uuid1', uuid })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        uuid1: await mfkdf2.derive.factors.uuid(uuid)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('question', async () => {
      const answer = ' Fido-'
      const normalizedAnswer = '-f_i%d#o ? '
      const question = 'What is the name of your first pet?'

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.question(answer, { id: 'question1', question })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        question1: await mfkdf.derive.factors.question(normalizedAnswer)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.question(answer, { id: 'question1', question })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        question1: await mfkdf2.derive.factors.question(normalizedAnswer)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('hotp', async () => {
      const secret = Buffer.from('abcdefghijklmnopqrst')

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.hotp({ id: 'hotp1', secret })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        hotp1: await mfkdf.derive.factors.hotp(241063)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.hotp({ id: 'hotp1', secret })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        hotp1: await mfkdf2.derive.factors.hotp(241063)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('totp', async () => {
      const secret = Buffer.from('abcdefghijklmnopqrst')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.totp({ id: 'totp1', secret, time })
      ], { id: 'key1' })

      const code = parseInt(
        speakeasy.totp({
          secret: secret.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        totp1: await mfkdf.derive.factors.totp(code, { time })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.totp({ id: 'totp1', secret, time })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        totp1: await mfkdf2.derive.factors.totp(code, { time })
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