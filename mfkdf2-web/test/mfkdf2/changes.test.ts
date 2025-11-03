/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import crypto from 'crypto';

suite('mfkdf2/changes', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  suite('key-size-256', () => {
    test('default', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
      setup.key.length.should.equal(32)
      derive.key.length.should.equal(32)
    })
  })

  suite('kdf-argon2id', () => {
    test('override/mismatch/time', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { time: 3 }
      )

      const derive1 = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1')
      })

      setup.policy.time = 4

      const derive2 = await mfkdf.derive.key(
        setup.policy,
        {
          password1: await mfkdf.derive.factors.password('password1')
        },
        false
      )

      derive1.key.toString('hex').should.not.equal(derive2.key.toString('hex'))
      derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
      derive2.key.toString('hex').should.not.equal(setup.key.toString('hex'))
    })

    test('override/mismatch/memory', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { memory: 1024 }
      )

      const derive1 = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1')
      })

      setup.policy.memory = 2048

      const derive2 = await mfkdf.derive.key(
        setup.policy,
        {
          password1: await mfkdf.derive.factors.password('password1')
        },
        false
      )

      derive1.key.toString('hex').should.not.equal(derive2.key.toString('hex'))
      derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
      derive2.key.toString('hex').should.not.equal(setup.key.toString('hex'))
    })

    test('override/matching', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { memory: 65536, time: 3 }
      )
      setup.policy.memory.should.equal(65536)
      setup.policy.time.should.equal(3)

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: await mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })
  })

  suite('encryption', () => {
    test('aes-256-ecb', async () => {
      const stretched = await crypto.randomBytes(32)
      const share = await crypto.randomBytes(32)

      const cipher = crypto.createCipheriv('AES-256-ECB', stretched, null)
      cipher.setAutoPadding(false)
      const pad = Buffer.concat([cipher.update(share), cipher.final()])

      const decipher = crypto.createDecipheriv('AES-256-ECB', stretched, null)
      decipher.setAutoPadding(false)
      const share2 = Buffer.concat([decipher.update(pad), decipher.final()])

      share2.toString('hex').should.equal(share.toString('hex'))
    })
  })
});