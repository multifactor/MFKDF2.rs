/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import { mfkdf as mfkdf2, uniffiInitAsync } from '../../src/api';
import { derivedKeyIsEqual } from './validation';

import mfkdf from 'mfkdf';
import speakeasy from 'speakeasy';
import crypto from 'crypto';

suite('differential/derive', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  // each factor individually with single factor
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

    test('hmacsha1', async () => {
      const secret = Buffer.from('abcdefghijklmnopqrst')

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.hmacsha1({ id: 'hmac1', secret })
      ], { id: 'key1' })

      const challenge = Buffer.from(setup.policy.factors[0].params.challenge, 'hex')
      const response = crypto.createHmac('sha1', secret).update(challenge).digest()

      const derive = await mfkdf.derive.key(setup.policy, {
        hmac1: await mfkdf.derive.factors.hmacsha1(response)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.hmacsha1({ id: 'hmac1', secret })
      ], { id: 'key1' })

      const challenge2 = Buffer.from(setup2.policy.factors[0].params.challenge, 'hex')
      const response2 = crypto.createHmac('sha1', secret).update(challenge2).digest()

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        hmac1: await mfkdf2.derive.factors.hmacsha1(response2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('passkey', async () => {
      const secret = Buffer.from(Array.from({ length: 32 }, (_, i) => i))

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.passkey(secret, { id: 'passkey1' })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        passkey1: await mfkdf.derive.factors.passkey(secret)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.passkey(secret, { id: 'passkey1' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        passkey1: await mfkdf2.derive.factors.passkey(secret)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('stack', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        stack1: await mfkdf.derive.factors.stack({
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2')
        })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        stack1: await mfkdf2.derive.factors.stack({
          password1: await mfkdf2.derive.factors.password('password1'),
          password2: await mfkdf2.derive.factors.password('password2')
        })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('ooba', async () => {
      const keyPair = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.ooba({ id: 'ooba1', key: keyPair.publicKey, params: { email: 'test@mfkdf.com' } })
      ], { id: 'key1' })

      const next = setup.policy.factors[0].params.next
      const decrypted = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair.privateKey,
        Buffer.from(next, 'hex')
      )
      const json = JSON.parse(Buffer.from(decrypted).toString())
      const code = json.code

      const derive = await mfkdf.derive.key(setup.policy, {
        ooba1: await mfkdf.derive.factors.ooba(code)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.ooba({ id: 'ooba1', key: keyPair.publicKey, params: { email: 'test@mfkdf.com' } })
      ], { id: 'key1' })
      const setup2Clone = JSON.parse(JSON.stringify(setup2))

      // purposely modify the setup2Clone to make it similar to the setup
      // next can't be equal due to rsa-oaep-256 usage of inner rng
      setup2Clone.policy.factors[0].params.next = setup.policy.factors[0].params.next
      // ext is browser specific nodejs modification
      setup2Clone.policy.factors[0].params.key.ext = true
      // hmac can't be equal due to next and ext being different
      setup2Clone.policy.hmac = setup.policy.hmac

      const next2 = setup2.policy.factors[0].params.next
      const decrypted2 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair.privateKey,
        Buffer.from(next2, 'hex')
      )
      const json2 = JSON.parse(Buffer.from(decrypted2).toString())
      const code2 = json2.code

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        ooba1: await mfkdf2.derive.factors.ooba(code2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))
      // Align ephemeral params for comparison only
      derive2.policy.factors[0].params.next = derive.policy.factors[0].params.next
      derive2.policy.factors[0].params.pad = derive.policy.factors[0].params.pad
      if (derive2.policy.factors[0].params.key) {
        derive2.policy.factors[0].params.key.ext = true
      }
      // Align HMAC for comparison only
      derive2.policy.hmac = derive.policy.hmac

      derivedKeyIsEqual(setup, setup2Clone).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })
  });

  // each factor inidividually and multiple factors
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

    test('uuid', async () => {
      const uuid1 = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
      const uuid2 = '550e8400-e29b-41d4-a716-446655440000'

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: uuid1 }),
        await mfkdf.setup.factors.uuid({ id: 'uuid2', uuid: uuid2 })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        uuid1: await mfkdf.derive.factors.uuid(uuid1),
        uuid2: await mfkdf.derive.factors.uuid(uuid2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.uuid({ id: 'uuid1', uuid: uuid1 }),
        await mfkdf2.setup.factors.uuid({ id: 'uuid2', uuid: uuid2 })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        uuid1: await mfkdf2.derive.factors.uuid(uuid1),
        uuid2: await mfkdf2.derive.factors.uuid(uuid2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('question', async () => {
      const answer1 = ' Fido-'
      const question1 = 'What is the name of your first pet?'
      const answer2 = 'New York'
      const question2 = 'What city were you born in?'

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.question(answer1, { id: 'question1', question: question1 }),
        await mfkdf.setup.factors.question(answer2, { id: 'question2', question: question2 })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        question1: await mfkdf.derive.factors.question(answer1),
        question2: await mfkdf.derive.factors.question(answer2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.question(answer1, { id: 'question1', question: question1 }),
        await mfkdf2.setup.factors.question(answer2, { id: 'question2', question: question2 })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        question1: await mfkdf2.derive.factors.question(answer1),
        question2: await mfkdf2.derive.factors.question(answer2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('hotp', async () => {
      const secret1 = Buffer.from('abcdefghijklmnopqrst')
      const secret2 = Buffer.from('zyxwvutsrqponmlkjihg')

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.hotp({ id: 'hotp1', secret: secret1 }),
        await mfkdf.setup.factors.hotp({ id: 'hotp2', secret: secret2 })
      ], { id: 'key1' })

      const params1 = setup.policy.factors[0].params
      const params2 = setup.policy.factors[1].params
      const counter1 = params1.counter
      const counter2 = params2.counter

      const code1 = parseInt(speakeasy.hotp({
        secret: secret1.toString('hex'),
        encoding: 'hex',
        counter: counter1,
        digits: 6,
        algorithm: 'sha1'
      }))
      const code2 = parseInt(speakeasy.hotp({
        secret: secret2.toString('hex'),
        encoding: 'hex',
        counter: counter2,
        digits: 6,
        algorithm: 'sha1'
      }))

      const derive = await mfkdf.derive.key(setup.policy, {
        hotp1: await mfkdf.derive.factors.hotp(code1),
        hotp2: await mfkdf.derive.factors.hotp(code2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.hotp({ id: 'hotp1', secret: secret1 }),
        await mfkdf2.setup.factors.hotp({ id: 'hotp2', secret: secret2 })
      ], { id: 'key1' })

      const params1_2 = setup2.policy.factors[0].params
      const params2_2 = setup2.policy.factors[1].params
      const counter1_2 = params1_2.counter
      const counter2_2 = params2_2.counter

      const code1_2 = parseInt(speakeasy.hotp({
        secret: secret1.toString('hex'),
        encoding: 'hex',
        counter: counter1_2,
        digits: 6,
        algorithm: 'sha1'
      }))
      const code2_2 = parseInt(speakeasy.hotp({
        secret: secret2.toString('hex'),
        encoding: 'hex',
        counter: counter2_2,
        digits: 6,
        algorithm: 'sha1'
      }))

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        hotp1: await mfkdf2.derive.factors.hotp(code1_2),
        hotp2: await mfkdf2.derive.factors.hotp(code2_2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('totp', async () => {
      const secret1 = Buffer.from('abcdefghijklmnopqrst')
      const secret2 = Buffer.from('zyxwvutsrqponmlkjihg')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.totp({ id: 'totp1', secret: secret1, time }),
        await mfkdf.setup.factors.totp({ id: 'totp2', secret: secret2, time })
      ], { id: 'key1' })

      const code1 = parseInt(
        speakeasy.totp({
          secret: secret1.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )
      const code2 = parseInt(
        speakeasy.totp({
          secret: secret2.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        totp1: await mfkdf.derive.factors.totp(code1, { time }),
        totp2: await mfkdf.derive.factors.totp(code2, { time })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.totp({ id: 'totp1', secret: secret1, time }),
        await mfkdf2.setup.factors.totp({ id: 'totp2', secret: secret2, time })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        totp1: await mfkdf2.derive.factors.totp(code1, { time }),
        totp2: await mfkdf2.derive.factors.totp(code2, { time })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('hmacsha1', async () => {
      const secret1 = Buffer.from('abcdefghijklmnopqrst')
      const secret2 = Buffer.from('zyxwvutsrqponmlkjihg')

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.hmacsha1({ id: 'hmac1', secret: secret1 }),
        await mfkdf.setup.factors.hmacsha1({ id: 'hmac2', secret: secret2 })
      ], { id: 'key1' })

      const challenge1 = Buffer.from(setup.policy.factors[0].params.challenge, 'hex')
      const response1 = crypto.createHmac('sha1', secret1).update(challenge1).digest()
      const challenge2 = Buffer.from(setup.policy.factors[1].params.challenge, 'hex')
      const response2 = crypto.createHmac('sha1', secret2).update(challenge2).digest()

      const derive = await mfkdf.derive.key(setup.policy, {
        hmac1: await mfkdf.derive.factors.hmacsha1(response1),
        hmac2: await mfkdf.derive.factors.hmacsha1(response2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.hmacsha1({ id: 'hmac1', secret: secret1 }),
        await mfkdf2.setup.factors.hmacsha1({ id: 'hmac2', secret: secret2 })
      ], { id: 'key1' })

      const challenge1_2 = Buffer.from(setup2.policy.factors[0].params.challenge, 'hex')
      const response1_2 = crypto.createHmac('sha1', secret1).update(challenge1_2).digest()
      const challenge2_2 = Buffer.from(setup2.policy.factors[1].params.challenge, 'hex')
      const response2_2 = crypto.createHmac('sha1', secret2).update(challenge2_2).digest()

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        hmac1: await mfkdf2.derive.factors.hmacsha1(response1_2),
        hmac2: await mfkdf2.derive.factors.hmacsha1(response2_2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('passkey', async () => {
      const secret1 = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
      const secret2 = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32))

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.passkey(secret1, { id: 'passkey1' }),
        await mfkdf.setup.factors.passkey(secret2, { id: 'passkey2' })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        passkey1: await mfkdf.derive.factors.passkey(secret1),
        passkey2: await mfkdf.derive.factors.passkey(secret2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.passkey(secret1, { id: 'passkey1' }),
        await mfkdf2.setup.factors.passkey(secret2, { id: 'passkey2' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        passkey1: await mfkdf2.derive.factors.passkey(secret1),
        passkey2: await mfkdf2.derive.factors.passkey(secret2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('stack', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        ], { id: 'stack1' }),
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ], { id: 'stack2' })
      ], { id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        stack1: await mfkdf.derive.factors.stack({
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2')
        }),
        stack2: await mfkdf.derive.factors.stack({
          password3: await mfkdf.derive.factors.password('password3'),
          password4: await mfkdf.derive.factors.password('password4')
        })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' })
        ], { id: 'stack1' }),
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf2.setup.factors.password('password4', { id: 'password4' })
        ], { id: 'stack2' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        stack1: await mfkdf2.derive.factors.stack({
          password1: await mfkdf2.derive.factors.password('password1'),
          password2: await mfkdf2.derive.factors.password('password2')
        }),
        stack2: await mfkdf2.derive.factors.stack({
          password3: await mfkdf2.derive.factors.password('password3'),
          password4: await mfkdf2.derive.factors.password('password4')
        })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('ooba', async () => {
      const keyPair1 = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )
      const keyPair2 = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.ooba({ id: 'ooba1', key: keyPair1.publicKey, params: { email: 'test1@mfkdf.com' } }),
        await mfkdf.setup.factors.ooba({ id: 'ooba2', key: keyPair2.publicKey, params: { email: 'test2@mfkdf.com' } })
      ], { id: 'key1' })

      const next1 = setup.policy.factors[0].params.next
      const decrypted1 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair1.privateKey,
        Buffer.from(next1, 'hex')
      )
      const json1 = JSON.parse(Buffer.from(decrypted1).toString())
      const code1 = json1.code

      const next2 = setup.policy.factors[1].params.next
      const decrypted2 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair2.privateKey,
        Buffer.from(next2, 'hex')
      )
      const json2 = JSON.parse(Buffer.from(decrypted2).toString())
      const code2 = json2.code

      const derive = await mfkdf.derive.key(setup.policy, {
        ooba1: await mfkdf.derive.factors.ooba(code1),
        ooba2: await mfkdf.derive.factors.ooba(code2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.ooba({ id: 'ooba1', key: keyPair1.publicKey, params: { email: 'test1@mfkdf.com' } }),
        await mfkdf2.setup.factors.ooba({ id: 'ooba2', key: keyPair2.publicKey, params: { email: 'test2@mfkdf.com' } })
      ], { id: 'key1' })
      const setup2Clone = JSON.parse(JSON.stringify(setup2))

      // purposely modify the setup2Clone to make it similar to the setup
      // next can't be equal due to rsa-oaep-256 usage of inner rng
      setup2Clone.policy.factors[0].params.next = setup.policy.factors[0].params.next
      setup2Clone.policy.factors[1].params.next = setup.policy.factors[1].params.next
      // ext is browser specific nodejs modification
      setup2Clone.policy.factors[0].params.key.ext = true
      setup2Clone.policy.factors[1].params.key.ext = true
      // hmac can't be equal due to next and ext being different
      setup2Clone.policy.hmac = setup.policy.hmac

      const next1_2 = setup2.policy.factors[0].params.next
      const decrypted1_2 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair1.privateKey,
        Buffer.from(next1_2, 'hex')
      )
      const json1_2 = JSON.parse(Buffer.from(decrypted1_2).toString())
      const code1_2 = json1_2.code

      const next2_2 = setup2.policy.factors[1].params.next
      const decrypted2_2 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair2.privateKey,
        Buffer.from(next2_2, 'hex')
      )
      const json2_2 = JSON.parse(Buffer.from(decrypted2_2).toString())
      const code2_2 = json2_2.code

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        ooba1: await mfkdf2.derive.factors.ooba(code1_2),
        ooba2: await mfkdf2.derive.factors.ooba(code2_2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))
      // Align ephemeral params for comparison only
      derive2.policy.factors[0].params.next = derive.policy.factors[0].params.next
      derive2.policy.factors[1].params.next = derive.policy.factors[1].params.next
      derive2.policy.factors[0].params.key.ext = true
      derive2.policy.factors[1].params.key.ext = true
      // Align HMAC for comparison only
      derive2.policy.hmac = derive.policy.hmac

      derivedKeyIsEqual(setup, setup2Clone).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })
  });

  // single factor combinations with partial threshold
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

    test('uuid', async () => {
      const uuid1 = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
      const uuid2 = '550e8400-e29b-41d4-a716-446655440000'
      const uuid3 = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: uuid1 }),
        await mfkdf.setup.factors.uuid({ id: 'uuid2', uuid: uuid2 }),
        await mfkdf.setup.factors.uuid({ id: 'uuid3', uuid: uuid3 })
      ], { threshold: 2, id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        uuid1: await mfkdf.derive.factors.uuid(uuid1),
        uuid2: await mfkdf.derive.factors.uuid(uuid2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.uuid({ id: 'uuid1', uuid: uuid1 }),
        await mfkdf2.setup.factors.uuid({ id: 'uuid2', uuid: uuid2 }),
        await mfkdf2.setup.factors.uuid({ id: 'uuid3', uuid: uuid3 })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        uuid1: await mfkdf2.derive.factors.uuid(uuid1),
        uuid2: await mfkdf2.derive.factors.uuid(uuid2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('question', async () => {
      const answer1 = ' Fido-'
      const question1 = 'What is the name of your first pet?'
      const answer2 = 'New York'
      const question2 = 'What city were you born in?'
      const answer3 = 'Blue'
      const question3 = 'What is your favorite color?'

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.question(answer1, { id: 'question1', question: question1 }),
        await mfkdf.setup.factors.question(answer2, { id: 'question2', question: question2 }),
        await mfkdf.setup.factors.question(answer3, { id: 'question3', question: question3 })
      ], { threshold: 2, id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        question1: await mfkdf.derive.factors.question(answer1),
        question2: await mfkdf.derive.factors.question(answer2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.question(answer1, { id: 'question1', question: question1 }),
        await mfkdf2.setup.factors.question(answer2, { id: 'question2', question: question2 }),
        await mfkdf2.setup.factors.question(answer3, { id: 'question3', question: question3 })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        question1: await mfkdf2.derive.factors.question(answer1),
        question2: await mfkdf2.derive.factors.question(answer2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('hotp', async () => {
      const secret1 = Buffer.from('abcdefghijklmnopqrst')
      const secret2 = Buffer.from('zyxwvutsrqponmlkjihg')
      const secret3 = Buffer.from('0123456789abcdefghij')

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.hotp({ id: 'hotp1', secret: secret1 }),
        await mfkdf.setup.factors.hotp({ id: 'hotp2', secret: secret2 }),
        await mfkdf.setup.factors.hotp({ id: 'hotp3', secret: secret3 })
      ], { threshold: 2, id: 'key1' })

      const params1 = setup.policy.factors[0].params
      const params2 = setup.policy.factors[1].params
      const counter1 = params1.counter
      const counter2 = params2.counter

      const code1 = parseInt(speakeasy.hotp({
        secret: secret1.toString('hex'),
        encoding: 'hex',
        counter: counter1,
        digits: 6,
        algorithm: 'sha1'
      }))
      const code2 = parseInt(speakeasy.hotp({
        secret: secret2.toString('hex'),
        encoding: 'hex',
        counter: counter2,
        digits: 6,
        algorithm: 'sha1'
      }))

      const derive = await mfkdf.derive.key(setup.policy, {
        hotp1: await mfkdf.derive.factors.hotp(code1),
        hotp2: await mfkdf.derive.factors.hotp(code2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.hotp({ id: 'hotp1', secret: secret1 }),
        await mfkdf2.setup.factors.hotp({ id: 'hotp2', secret: secret2 }),
        await mfkdf2.setup.factors.hotp({ id: 'hotp3', secret: secret3 })
      ], { threshold: 2, id: 'key1' })

      const params1_2 = setup2.policy.factors[0].params
      const params2_2 = setup2.policy.factors[1].params
      const counter1_2 = params1_2.counter
      const counter2_2 = params2_2.counter

      const code1_2 = parseInt(speakeasy.hotp({
        secret: secret1.toString('hex'),
        encoding: 'hex',
        counter: counter1_2,
        digits: 6,
        algorithm: 'sha1'
      }))
      const code2_2 = parseInt(speakeasy.hotp({
        secret: secret2.toString('hex'),
        encoding: 'hex',
        counter: counter2_2,
        digits: 6,
        algorithm: 'sha1'
      }))

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        hotp1: await mfkdf2.derive.factors.hotp(code1_2),
        hotp2: await mfkdf2.derive.factors.hotp(code2_2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('totp', async () => {
      const secret1 = Buffer.from('abcdefghijklmnopqrst')
      const secret2 = Buffer.from('zyxwvutsrqponmlkjihg')
      const secret3 = Buffer.from('0123456789abcdefghij')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.totp({ id: 'totp1', secret: secret1, time }),
        await mfkdf.setup.factors.totp({ id: 'totp2', secret: secret2, time }),
        await mfkdf.setup.factors.totp({ id: 'totp3', secret: secret3, time })
      ], { threshold: 2, id: 'key1' })

      const code1 = parseInt(
        speakeasy.totp({
          secret: secret1.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )
      const code2 = parseInt(
        speakeasy.totp({
          secret: secret2.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        totp1: await mfkdf.derive.factors.totp(code1, { time }),
        totp2: await mfkdf.derive.factors.totp(code2, { time })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.totp({ id: 'totp1', secret: secret1, time }),
        await mfkdf2.setup.factors.totp({ id: 'totp2', secret: secret2, time }),
        await mfkdf2.setup.factors.totp({ id: 'totp3', secret: secret3, time })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        totp1: await mfkdf2.derive.factors.totp(code1, { time }),
        totp2: await mfkdf2.derive.factors.totp(code2, { time })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('hmacsha1', async () => {
      const secret1 = Buffer.from('abcdefghijklmnopqrst')
      const secret2 = Buffer.from('zyxwvutsrqponmlkjihg')
      const secret3 = Buffer.from('0123456789abcdefghij')

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.hmacsha1({ id: 'hmac1', secret: secret1 }),
        await mfkdf.setup.factors.hmacsha1({ id: 'hmac2', secret: secret2 }),
        await mfkdf.setup.factors.hmacsha1({ id: 'hmac3', secret: secret3 })
      ], { threshold: 2, id: 'key1' })

      const challenge1 = Buffer.from(setup.policy.factors[0].params.challenge, 'hex')
      const response1 = crypto.createHmac('sha1', secret1).update(challenge1).digest()
      const challenge2 = Buffer.from(setup.policy.factors[1].params.challenge, 'hex')
      const response2 = crypto.createHmac('sha1', secret2).update(challenge2).digest()

      const derive = await mfkdf.derive.key(setup.policy, {
        hmac1: await mfkdf.derive.factors.hmacsha1(response1),
        hmac2: await mfkdf.derive.factors.hmacsha1(response2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.hmacsha1({ id: 'hmac1', secret: secret1 }),
        await mfkdf2.setup.factors.hmacsha1({ id: 'hmac2', secret: secret2 }),
        await mfkdf2.setup.factors.hmacsha1({ id: 'hmac3', secret: secret3 })
      ], { threshold: 2, id: 'key1' })

      const challenge1_2 = Buffer.from(setup2.policy.factors[0].params.challenge, 'hex')
      const response1_2 = crypto.createHmac('sha1', secret1).update(challenge1_2).digest()
      const challenge2_2 = Buffer.from(setup2.policy.factors[1].params.challenge, 'hex')
      const response2_2 = crypto.createHmac('sha1', secret2).update(challenge2_2).digest()

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        hmac1: await mfkdf2.derive.factors.hmacsha1(response1_2),
        hmac2: await mfkdf2.derive.factors.hmacsha1(response2_2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('passkey', async () => {
      const secret1 = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
      const secret2 = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32))
      const secret3 = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 64))

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.passkey(secret1, { id: 'passkey1' }),
        await mfkdf.setup.factors.passkey(secret2, { id: 'passkey2' }),
        await mfkdf.setup.factors.passkey(secret3, { id: 'passkey3' })
      ], { threshold: 2, id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        passkey1: await mfkdf.derive.factors.passkey(secret1),
        passkey2: await mfkdf.derive.factors.passkey(secret2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.passkey(secret1, { id: 'passkey1' }),
        await mfkdf2.setup.factors.passkey(secret2, { id: 'passkey2' }),
        await mfkdf2.setup.factors.passkey(secret3, { id: 'passkey3' })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        passkey1: await mfkdf2.derive.factors.passkey(secret1),
        passkey2: await mfkdf2.derive.factors.passkey(secret2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('stack', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        ], { id: 'stack1' }),
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ], { id: 'stack2' }),
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password5', { id: 'password5' }),
          await mfkdf.setup.factors.password('password6', { id: 'password6' })
        ], { id: 'stack3' })
      ], { threshold: 2, id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        stack1: await mfkdf.derive.factors.stack({
          password1: await mfkdf.derive.factors.password('password1'),
          password2: await mfkdf.derive.factors.password('password2')
        }),
        stack2: await mfkdf.derive.factors.stack({
          password3: await mfkdf.derive.factors.password('password3'),
          password4: await mfkdf.derive.factors.password('password4')
        })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.password('password2', { id: 'password2' })
        ], { id: 'stack1' }),
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf2.setup.factors.password('password4', { id: 'password4' })
        ], { id: 'stack2' }),
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password5', { id: 'password5' }),
          await mfkdf2.setup.factors.password('password6', { id: 'password6' })
        ], { id: 'stack3' })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        stack1: await mfkdf2.derive.factors.stack({
          password1: await mfkdf2.derive.factors.password('password1'),
          password2: await mfkdf2.derive.factors.password('password2')
        }),
        stack2: await mfkdf2.derive.factors.stack({
          password3: await mfkdf2.derive.factors.password('password3'),
          password4: await mfkdf2.derive.factors.password('password4')
        })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('ooba', async () => {
      const keyPair1 = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )
      const keyPair2 = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )
      const keyPair3 = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.ooba({ id: 'ooba1', key: keyPair1.publicKey, params: { email: 'test1@mfkdf.com' } }),
        await mfkdf.setup.factors.ooba({ id: 'ooba2', key: keyPair2.publicKey, params: { email: 'test2@mfkdf.com' } }),
        await mfkdf.setup.factors.ooba({ id: 'ooba3', key: keyPair3.publicKey, params: { email: 'test3@mfkdf.com' } })
      ], { threshold: 2, id: 'key1' })

      const next1 = setup.policy.factors[0].params.next
      const decrypted1 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair1.privateKey,
        Buffer.from(next1, 'hex')
      )
      const json1 = JSON.parse(Buffer.from(decrypted1).toString())
      const code1 = json1.code

      const next2 = setup.policy.factors[1].params.next
      const decrypted2 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair2.privateKey,
        Buffer.from(next2, 'hex')
      )
      const json2 = JSON.parse(Buffer.from(decrypted2).toString())
      const code2 = json2.code

      const derive = await mfkdf.derive.key(setup.policy, {
        ooba1: await mfkdf.derive.factors.ooba(code1),
        ooba2: await mfkdf.derive.factors.ooba(code2)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.ooba({ id: 'ooba1', key: keyPair1.publicKey, params: { email: 'test1@mfkdf.com' } }),
        await mfkdf2.setup.factors.ooba({ id: 'ooba2', key: keyPair2.publicKey, params: { email: 'test2@mfkdf.com' } }),
        await mfkdf2.setup.factors.ooba({ id: 'ooba3', key: keyPair3.publicKey, params: { email: 'test3@mfkdf.com' } })
      ], { threshold: 2, id: 'key1' })
      const setup2Clone = JSON.parse(JSON.stringify(setup2))

      // purposely modify the setup2Clone to make it similar to the setup
      // next can't be equal due to rsa-oaep-256 usage of inner rng
      setup2Clone.policy.factors[0].params.next = setup.policy.factors[0].params.next
      setup2Clone.policy.factors[1].params.next = setup.policy.factors[1].params.next
      setup2Clone.policy.factors[2].params.next = setup.policy.factors[2].params.next
      // ext is browser specific nodejs modification
      setup2Clone.policy.factors[0].params.key.ext = true
      setup2Clone.policy.factors[1].params.key.ext = true
      setup2Clone.policy.factors[2].params.key.ext = true
      // hmac can't be equal due to next and ext being different
      setup2Clone.policy.hmac = setup.policy.hmac

      const next1_2 = setup2.policy.factors[0].params.next
      const decrypted1_2 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair1.privateKey,
        Buffer.from(next1_2, 'hex')
      )
      const json1_2 = JSON.parse(Buffer.from(decrypted1_2).toString())
      const code1_2 = json1_2.code

      const next2_2 = setup2.policy.factors[1].params.next
      const decrypted2_2 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair2.privateKey,
        Buffer.from(next2_2, 'hex')
      )
      const json2_2 = JSON.parse(Buffer.from(decrypted2_2).toString())
      const code2_2 = json2_2.code

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        ooba1: await mfkdf2.derive.factors.ooba(code1_2),
        ooba2: await mfkdf2.derive.factors.ooba(code2_2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))
      // Align ephemeral params for comparison only
      derive2.policy.factors[0].params.next = derive.policy.factors[0].params.next
      derive2.policy.factors[1].params.next = derive.policy.factors[1].params.next
      derive2.policy.factors[2].params.next = derive.policy.factors[2].params.next
      derive2.policy.factors[0].params.key.ext = true
      derive2.policy.factors[1].params.key.ext = true
      derive2.policy.factors[2].params.key.ext = true
      // Align HMAC for comparison only
      derive2.policy.hmac = derive.policy.hmac

      derivedKeyIsEqual(setup, setup2Clone).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })
  });

  // factor combinations with partial threshold with stack factors
  suite('factor combinations', () => {
    test('password + question + uuid', async () => {
      const answer = ' Fido-'
      const question = 'What is the name of your first pet?'
      const uuid = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.question(answer, { id: 'question1', question }),
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid })
      ], { threshold: 2, id: 'key1' })

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        question1: await mfkdf.derive.factors.question(answer)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.question(answer, { id: 'question1', question }),
        await mfkdf2.setup.factors.uuid({ id: 'uuid1', uuid })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        question1: await mfkdf2.derive.factors.question(answer)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('password + question + hotp', async () => {
      const answer = ' Fido-'
      const question = 'What is the name of your first pet?'
      const secret = Buffer.from('abcdefghijklmnopqrst')

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.question(answer, { id: 'question1', question }),
        await mfkdf.setup.factors.hotp({ id: 'hotp1', secret })
      ], { threshold: 2, id: 'key1' })

      const params = setup.policy.factors[2].params
      const counter = params.counter
      const code = parseInt(speakeasy.hotp({
        secret: secret.toString('hex'),
        encoding: 'hex',
        counter: counter,
        digits: 6,
        algorithm: 'sha1'
      }))

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        hotp1: await mfkdf.derive.factors.hotp(code)
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.question(answer, { id: 'question1', question }),
        await mfkdf2.setup.factors.hotp({ id: 'hotp1', secret })
      ], { threshold: 2, id: 'key1' })

      const params2 = setup2.policy.factors[2].params
      const counter2 = params2.counter
      const code2 = parseInt(speakeasy.hotp({
        secret: secret.toString('hex'),
        encoding: 'hex',
        counter: counter2,
        digits: 6,
        algorithm: 'sha1'
      }))

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        hotp1: await mfkdf2.derive.factors.hotp(code2)
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('password + question + totp + hotp', async () => {
      const answer = ' Fido-'
      const question = 'What is the name of your first pet?'
      const totpSecret = Buffer.from('abcdefghijklmnopqrst')
      const hotpSecret = Buffer.from('zyxwvutsrqponmlkjihg')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.question(answer, { id: 'question1', question }),
        await mfkdf.setup.factors.totp({ id: 'totp1', secret: totpSecret, time }),
        await mfkdf.setup.factors.hotp({ id: 'hotp1', secret: hotpSecret })
      ], { threshold: 2, id: 'key1' })

      const totpCode = parseInt(
        speakeasy.totp({
          secret: totpSecret.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        totp1: await mfkdf.derive.factors.totp(totpCode, { time })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.question(answer, { id: 'question1', question }),
        await mfkdf2.setup.factors.totp({ id: 'totp1', secret: totpSecret, time }),
        await mfkdf2.setup.factors.hotp({ id: 'hotp1', secret: hotpSecret })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        totp1: await mfkdf2.derive.factors.totp(totpCode, { time })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('password + passkey + totp', async () => {
      const passkeySecret = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
      const totpSecret = Buffer.from('abcdefghijklmnopqrst')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.passkey(passkeySecret, { id: 'passkey1' }),
        await mfkdf.setup.factors.totp({ id: 'totp1', secret: totpSecret, time })
      ], { threshold: 2, id: 'key1' })

      const code = parseInt(
        speakeasy.totp({
          secret: totpSecret.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1'),
        totp1: await mfkdf.derive.factors.totp(code, { time })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.passkey(passkeySecret, { id: 'passkey1' }),
        await mfkdf2.setup.factors.totp({ id: 'totp1', secret: totpSecret, time })
      ], { threshold: 2, id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        password1: await mfkdf2.derive.factors.password('password1'),
        totp1: await mfkdf2.derive.factors.totp(code, { time })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('password + ooba + totp', async () => {
      const keyPair = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )
      const totpSecret = Buffer.from('abcdefghijklmnopqrst')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.ooba({ id: 'ooba1', key: keyPair.publicKey, params: { email: 'test@mfkdf.com' } }),
        await mfkdf.setup.factors.totp({ id: 'totp1', secret: totpSecret, time })
      ], { threshold: 2, id: 'key1' })

      const next = setup.policy.factors[1].params.next
      const decrypted = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair.privateKey,
        Buffer.from(next, 'hex')
      )
      const json = JSON.parse(Buffer.from(decrypted).toString())
      const code = json.code

      const totpCode = parseInt(
        speakeasy.totp({
          secret: totpSecret.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        ooba1: await mfkdf.derive.factors.ooba(code),
        totp1: await mfkdf.derive.factors.totp(totpCode, { time })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf2.setup.factors.ooba({ id: 'ooba1', key: keyPair.publicKey, params: { email: 'test@mfkdf.com' } }),
        await mfkdf2.setup.factors.totp({ id: 'totp1', secret: totpSecret, time })
      ], { threshold: 2, id: 'key1' })
      const setup2Clone = JSON.parse(JSON.stringify(setup2))

      // purposely modify the setup2Clone to make it similar to the setup
      // next can't be equal due to rsa-oaep-256 usage of inner rng
      setup2Clone.policy.factors[1].params.next = setup.policy.factors[1].params.next
      // ext is browser specific nodejs modification
      setup2Clone.policy.factors[1].params.key.ext = true
      // hmac can't be equal due to next and ext being different
      setup2Clone.policy.hmac = setup.policy.hmac

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        ooba1: await mfkdf2.derive.factors.ooba(code),
        totp1: await mfkdf2.derive.factors.totp(totpCode, { time })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))
      // Align ephemeral params for comparison only
      derive2.policy.factors[1].params.next = derive.policy.factors[1].params.next
      derive2.policy.factors[1].params.key.ext = true
      // Align HMAC for comparison only
      derive2.policy.hmac = derive.policy.hmac

      derivedKeyIsEqual(setup, setup2Clone).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('stack: password-question-uuid', async () => {
      const answer = ' Fido-'
      const question = 'What is the name of your first pet?'
      const uuid = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.question(answer, { id: 'question1', question }),
          await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid })
        ], { id: 'stack1' })
      ], { id: 'key1' })


      const derive = await mfkdf.derive.key(setup.policy, {
        stack1: await mfkdf.derive.factors.stack({
          password1: await mfkdf.derive.factors.password('password1'),
          question1: await mfkdf.derive.factors.question(answer),
          uuid1: await mfkdf.derive.factors.uuid(uuid)
        })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.question(answer, { id: 'question1', question }),
          await mfkdf2.setup.factors.uuid({ id: 'uuid1', uuid })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        stack1: await mfkdf2.derive.factors.stack({
          password1: await mfkdf2.derive.factors.password('password1'),
          question1: await mfkdf2.derive.factors.question(answer),
          uuid1: await mfkdf2.derive.factors.uuid(uuid)
        })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('stack: password-question-hotp', async () => {
      const answer = ' Fido-'
      const question = 'What is the name of your first pet?'
      const secret = Buffer.from('abcdefghijklmnopqrst')

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.question(answer, { id: 'question1', question }),
          await mfkdf.setup.factors.hotp({ id: 'hotp1', secret })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const stackParams = setup.policy.factors[0].params
      const hotpParams = stackParams.factors.find((f: any) => f.id === 'hotp1').params
      const counter = hotpParams.counter
      const code = parseInt(speakeasy.hotp({
        secret: secret.toString('hex'),
        encoding: 'hex',
        counter: counter,
        digits: 6,
        algorithm: 'sha1'
      }))

      const derive = await mfkdf.derive.key(setup.policy, {
        stack1: await mfkdf.derive.factors.stack({
          password1: await mfkdf.derive.factors.password('password1'),
          question1: await mfkdf.derive.factors.question(answer),
          hotp1: await mfkdf.derive.factors.hotp(code)
        })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.question(answer, { id: 'question1', question }),
          await mfkdf2.setup.factors.hotp({ id: 'hotp1', secret })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const stackParams2 = setup2.policy.factors[0].params
      const hotpParams2 = stackParams2.factors.find((f: any) => f.id === 'hotp1').params
      const counter2 = hotpParams2.counter
      const code2 = parseInt(speakeasy.hotp({
        secret: secret.toString('hex'),
        encoding: 'hex',
        counter: counter2,
        digits: 6,
        algorithm: 'sha1'
      }))

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        stack1: await mfkdf2.derive.factors.stack({
          password1: await mfkdf2.derive.factors.password('password1'),
          question1: await mfkdf2.derive.factors.question(answer),
          hotp1: await mfkdf2.derive.factors.hotp(code2)
        })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('stack: password-question-totp', async () => {
      const answer = ' Fido-'
      const question = 'What is the name of your first pet?'
      const secret = Buffer.from('abcdefghijklmnopqrst')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.question(answer, { id: 'question1', question }),
          await mfkdf.setup.factors.totp({ id: 'totp1', secret, time })
        ], { id: 'stack1' })
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
        stack1: await mfkdf.derive.factors.stack({
          password1: await mfkdf.derive.factors.password('password1'),
          question1: await mfkdf.derive.factors.question(answer),
          totp1: await mfkdf.derive.factors.totp(code, { time })
        })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.question(answer, { id: 'question1', question }),
          await mfkdf2.setup.factors.totp({ id: 'totp1', secret, time })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        stack1: await mfkdf2.derive.factors.stack({
          password1: await mfkdf2.derive.factors.password('password1'),
          question1: await mfkdf2.derive.factors.question(answer),
          totp1: await mfkdf2.derive.factors.totp(code, { time })
        })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('stack: password-passkey-totp', async () => {
      const passkeySecret = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
      const totpSecret = Buffer.from('abcdefghijklmnopqrst')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.passkey(passkeySecret, { id: 'passkey1' }),
          await mfkdf.setup.factors.totp({ id: 'totp1', secret: totpSecret, time })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const code = parseInt(
        speakeasy.totp({
          secret: totpSecret.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        stack1: await mfkdf.derive.factors.stack({
          password1: await mfkdf.derive.factors.password('password1'),
          passkey1: await mfkdf.derive.factors.passkey(passkeySecret),
          totp1: await mfkdf.derive.factors.totp(code, { time })
        })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.passkey(passkeySecret, { id: 'passkey1' }),
          await mfkdf2.setup.factors.totp({ id: 'totp1', secret: totpSecret, time })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        stack1: await mfkdf2.derive.factors.stack({
          password1: await mfkdf2.derive.factors.password('password1'),
          passkey1: await mfkdf2.derive.factors.passkey(passkeySecret),
          totp1: await mfkdf2.derive.factors.totp(code, { time })
        })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))

      derivedKeyIsEqual(setup, setup2).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })

    test('stack: password-ooba-totp', async () => {
      const keyPair = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )
      const totpSecret = Buffer.from('abcdefghijklmnopqrst')
      const time = 1

      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.ooba({ id: 'ooba1', key: keyPair.publicKey, params: { email: 'test@mfkdf.com' } }),
          await mfkdf.setup.factors.totp({ id: 'totp1', secret: totpSecret, time })
        ], { id: 'stack1' })
      ], { id: 'key1' })

      const stackParams = setup.policy.factors[0].params
      const oobaParams = stackParams.factors.find((f: any) => f.id === 'ooba1').params
      const next = oobaParams.next
      const decrypted = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair.privateKey,
        Buffer.from(next, 'hex')
      )
      const json = JSON.parse(Buffer.from(decrypted).toString())
      const oobaCode = json.code

      const totpCode = parseInt(
        speakeasy.totp({
          secret: totpSecret.toString('hex'),
          encoding: 'hex',
          step: 30,
          algorithm: 'sha1',
          digits: 6,
          time
        })
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        stack1: await mfkdf.derive.factors.stack({
          password1: await mfkdf.derive.factors.password('password1'),
          ooba1: await mfkdf.derive.factors.ooba(oobaCode),
          totp1: await mfkdf.derive.factors.totp(totpCode, { time })
        })
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      const setup2 = await mfkdf2.setup.key([
        await mfkdf2.setup.factors.stack([
          await mfkdf2.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf2.setup.factors.ooba({ id: 'ooba1', key: keyPair.publicKey, params: { email: 'test@mfkdf.com' } }),
          await mfkdf2.setup.factors.totp({ id: 'totp1', secret: totpSecret, time })
        ], { id: 'stack1' })
      ], { id: 'key1' })
      const setup2Clone = JSON.parse(JSON.stringify(setup2))

      // purposely modify the setup2Clone to make it similar to the setup
      // next can't be equal due to rsa-oaep-256 usage of inner rng
      const stackParams2Clone = setup2Clone.policy.factors[0].params
      const oobaFactor2Clone = stackParams2Clone.factors.find((f: any) => f.id === 'ooba1')
      const oobaParams2Clone = typeof oobaFactor2Clone.params === 'string'
        ? JSON.parse(oobaFactor2Clone.params)
        : oobaFactor2Clone.params
      const setupOobaFactor = setup.policy.factors[0].params.factors.find((f: any) => f.id === 'ooba1')
      const setupOobaParams = typeof setupOobaFactor.params === 'string'
        ? JSON.parse(setupOobaFactor.params)
        : setupOobaFactor.params
      oobaParams2Clone.next = setupOobaParams.next
      // ext is browser specific nodejs modification
      if (oobaParams2Clone.key) {
        oobaParams2Clone.key.ext = true
      }
      // Update the params back to the factor
      oobaFactor2Clone.params = oobaParams2Clone
      // hmac can't be equal due to next and ext being different
      setup2Clone.policy.hmac = setup.policy.hmac

      const stackParams2 = setup2.policy.factors[0].params
      const oobaParams2 = stackParams2.factors.find((f: any) => f.id === 'ooba1').params
      const next2 = oobaParams2.next
      const decrypted2 = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair.privateKey,
        Buffer.from(next2, 'hex')
      )
      const json2 = JSON.parse(Buffer.from(decrypted2).toString())
      const oobaCode2 = json2.code

      const derive2 = await mfkdf2.derive.key(setup2.policy, {
        stack1: await mfkdf2.derive.factors.stack({
          password1: await mfkdf2.derive.factors.password('password1'),
          ooba1: await mfkdf2.derive.factors.ooba(oobaCode2),
          totp1: await mfkdf2.derive.factors.totp(totpCode, { time })
        })
      })

      derive2.key.toString('hex').should.equal(setup2.key.toString('hex'))
      // Align ephemeral params for comparison only
      const deriveStackParams = derive.policy.factors[0].params
      const deriveOobaParams = deriveStackParams.factors.find((f: any) => f.id === 'ooba1').params
      const derive2StackParams = derive2.policy.factors[0].params
      const derive2OobaParams = derive2StackParams.factors.find((f: any) => f.id === 'ooba1').params
      derive2OobaParams.next = deriveOobaParams.next
      if (derive2OobaParams.key) {
        derive2OobaParams.key.ext = true
      }
      // Align HMAC for comparison only
      derive2.policy.hmac = derive.policy.hmac

      derivedKeyIsEqual(setup, setup2Clone).should.be.true
      derivedKeyIsEqual(derive, derive2).should.be.true
    })
  })

  suite('stack policy', () => { })

  suite('reconstitution', () => { })
});