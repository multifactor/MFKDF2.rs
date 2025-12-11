/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import crypto from 'crypto';

function hotpCode(
  secret: Buffer,
  counter: number | bigint,
  digits: number,
  algorithm: string = 'sha1'
) {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algorithm.toLowerCase(), secret).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return binary % 10 ** digits;
}

function totpCode(
  secret: Buffer,
  timeMs: number | bigint,
  step: number,
  digits: number,
  algorithm: string = 'sha1'
) {
  const counter = BigInt(Math.floor(Number(timeMs) / (step * 1000)));
  return hotpCode(secret, counter, digits, algorithm);
}

suite('derive/outputs', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
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

    derive.outputs.hmacsha1.secret.should.be.an('array')
    derive.outputs.hmacsha1.secret.length.should.equal(32)

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

    derive.outputs.uuid.should.have.property('uuid')
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

    derive.outputs.question.strength.should.be.an('object')
    derive.outputs.question.strength.score.should.be.a('number')
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

    derive.outputs.ooba.should.deep.equal({})
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

    derive.outputs.password.strength.should.be.an('object')
    derive.outputs.password.strength.score.should.be.a('number')
    setup.outputs.should.deep.equal(derive.outputs)
  })

  test('hotp', async () => {
    const secret = Buffer.from('abcdefghijklmnopqrst')
    const setup = await mfkdf.setup.key([await mfkdf.setup.factors.hotp({ secret })])

    const params = setup.policy.factors[0].params
    const algorithm = (params.hash || 'sha1').toString().toLowerCase()
    const code = hotpCode(secret, params.counter, params.digits, algorithm)

    const derive = await mfkdf.derive.key(setup.policy, {
      hotp: await mfkdf.derive.factors.hotp(code)
    })

    derive.outputs.hotp.should.include.keys(
      'scheme',
      'type',
      'label',
      'secret',
      'issuer',
      'algorithm',
      'digits',
      'counter',
      'uri'
    )
    Buffer.from(derive.outputs.hotp.secret).length.should.equal(20)
    derive.outputs.hotp.digits.should.equal(params.digits)
  })

  test('totp', async () => {
    const secret = Buffer.from('abcdefghijklmnopqrst')
    const start = Date.now()
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.totp({ secret, time: start, window: 5, step: 30 })
    ])

    const params = setup.policy.factors[0].params
    const algorithm = (params.hash || 'sha1').toString().toLowerCase()
    const code = totpCode(
      Buffer.from(setup.outputs.totp.secret),
      params.start,
      params.step,
      params.digits,
      algorithm
    )

    const derive = await mfkdf.derive.key(setup.policy, {
      totp: await mfkdf.derive.factors.totp(code, { time: BigInt(params.start) })
    })

    derive.outputs.totp.should.include.keys(
      'scheme',
      'type',
      'label',
      'secret',
      'issuer',
      'algorithm',
      'digits',
      'period',
      'uri'
    )
    Buffer.from(derive.outputs.totp.secret).length.should.equal(20)
    derive.outputs.totp.should.have.property('period', 0)
    derive.outputs.totp.should.have.property('digits', 0)
  })

  test('passkey', async () => {
    const secret = crypto.randomBytes(32)
    const setup = await mfkdf.setup.key([await mfkdf.setup.factors.passkey(secret)])

    const derive = await mfkdf.derive.key(setup.policy, {
      passkey: await mfkdf.derive.factors.passkey(secret)
    })

    derive.outputs.passkey.should.deep.equal({})
  })

  test('persisted', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2 }
    )

    const share = await setup.persistFactor('password2')

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: await mfkdf.derive.factors.password('password1'),
      password2: await mfkdf.derive.factors.persisted(share)
    })

    derive.outputs.should.have.property('password1')
    derive.outputs.should.not.have.property('password2')
    derive.outputs.password1.strength.should.be.an('object')
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

  test('stack structure', async () => {
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

    derive.outputs.stack.should.include.keys('policy', 'key', 'secret', 'shares', 'outputs')
    setup.outputs.should.deep.equal(derive.outputs)
  })
})