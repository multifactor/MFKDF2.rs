/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { initRustLogging, LogLevel, uniffiInitAsync } from '../../src/api';
import crypto from 'crypto';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2';

suite('derive/outputs', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
    await initRustLogging(LogLevel.Debug);
  });

  test('stack', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.stack([
        await mfkdf.setup.factors.uuid({
          id: 'uuid1',
          uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
        }),
        await mfkdf.setup.factors.uuid({
          id: 'uuid2',
          uuid: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'
        })
      ]),
      await mfkdf.setup.factors.uuid({
        id: 'uuid3',
        uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b'
      })
    ])

    delete setup.outputs.stack.entropy

    const derive = await mfkdf.derive.key(setup.policy, {
      stack: await mfkdf.derive.factors.stack({
        uuid1: await mfkdf.derive.factors.uuid(
          '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
        ),
        uuid2: await mfkdf.derive.factors.uuid(
          '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'
        )
      }),
      uuid3: await mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    })

    delete derive.outputs.stack.entropy

    setup.outputs.should.deep.equal(derive.outputs)
  })

  test('hmacsha1', async () => {
    const setup = await mfkdf.setup.key([await mfkdf.setup.factors.hmacsha1()])

    const secret = Buffer.from(setup.outputs.hmacsha1.secret)
    const challenge = Buffer.from(setup.policy.factors[0].params.challenge, 'hex')
    const response = crypto
      .createHmac('sha1', secret)
      .update(challenge)
      .digest()

    const derive = await mfkdf.derive.key(setup.policy, {
      hmacsha1: await mfkdf.derive.factors.hmacsha1(response)
    })

    setup.outputs.should.not.deep.equal(derive.outputs)
  })

  test('uuid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({
        uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
      })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid: await mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    setup.outputs.should.deep.equal(derive.outputs)
  })

  test('question', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.question('Fido')
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      question: await mfkdf.derive.factors.question('Fido')
    })

    setup.outputs.question.strength.calc_time = null
    derive.outputs.question.strength.calc_time = null

    setup.outputs.should.deep.equal(derive.outputs)
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
      await mfkdf.setup.factors.ooba({
        key: keyPair.publicKey,
        params: { email: 'test@mfkdf.com' }
      })
    ])

    const next = setup.policy.factors[0].params.next
    const decrypted = await crypto.webcrypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      keyPair.privateKey,
      Buffer.from(next, 'hex')
    )
    const code = JSON.parse(Buffer.from(decrypted).toString()).code

    const derive = await mfkdf.derive.key(setup.policy, {
      ooba: await mfkdf.derive.factors.ooba(code)
    })

    setup.outputs.should.deep.equal(derive.outputs)
  })

  test('password', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password')
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      password: await mfkdf.derive.factors.password('password')
    })

    setup.outputs.password.strength.calc_time = null
    derive.outputs.password.strength.calc_time = null

    setup.outputs.should.deep.equal(derive.outputs)
  })

  test('multiple', async () => {
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
    )

    setup.outputs.should.deep.equal({
      uuid1: { uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' },
      uuid2: { uuid: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed' },
      uuid3: { uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b' }
    })

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: await mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'),
      uuid3: await mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    })

    derive.outputs.should.deep.equal({
      uuid1: { uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' },
      uuid3: { uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b' }
    })
  })
})