/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();
import Ajv from 'ajv';
import policySchema from '../../../public/schema/v2.0.0/policy.json';
const ajv = new Ajv();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../src/api';
import { Mfkdf2Error } from '../../src/generated/web/mfkdf2.js';

suite('setup/key', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('default', async () => {
    const key = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('hello')
    ])
    ajv.validate(policySchema, key.policy).should.be.true
  })

  suite('id', () => {
    test('default', async () => {
      const { policy } = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('hello')
      ])
      policy.$id.should.be.a('string')
    })

    test('valid', async () => {
      const { policy } = await mfkdf.setup.key(
        [await mfkdf.setup.factors.password('hello')],
        { id: 'hello-world' }
      )
      policy.$id.should.equal('hello-world')
    })

    /* invalid test
    test('invalid/type', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { id: 12345 })
        .should.be.rejectedWith(TypeError)
    })
    */

    test('invalid/range', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { id: '' })
        .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
    })
  })

  suite('threshold', () => {
    test('default', async () => {
      const { policy } = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('hello', { id: 'password1' }),
        await mfkdf.setup.factors.password('hello', { id: 'password2' })
      ])
      policy.threshold.should.equal(2)
    })

    test('valid', async () => {
      const { policy } = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('hello', { id: 'password1' }),
          await mfkdf.setup.factors.password('hello', { id: 'password2' })
        ],
        { threshold: 1 }
      )
      policy.threshold.should.equal(1)
    })

    /* invalid test
    test('invalid/type', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], {
          threshold: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })
    */

    test('invalid/range', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { threshold: 0 })
        .should.be.rejectedWith(Mfkdf2Error.InvalidThreshold)

      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { threshold: 2 })
        .should.be.rejectedWith(Mfkdf2Error.InvalidThreshold)
    })
  })

  suite('salt', () => {
    test('default', async () => {
      const { policy } = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('hello')
      ])
      const salt = Buffer.from(policy.salt, 'base64')
      salt.length.should.equal(32)
    })

    test('valid', async () => {
      const { policy } = await mfkdf.setup.key(
        [await mfkdf.setup.factors.password('hello')],
        { salt: Buffer.from('12345678123456781234567812345678') }
      )
      policy.salt.should.equal(Buffer.from('12345678123456781234567812345678').toString('base64'))
    })

    /* invalid test
    test('invalid/type', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { salt: 'hello' })
        .should.be.rejectedWith(TypeError)
    })
    */
  })

  suite('factors', () => {
    /* this can't work with our current api
    test('valid', async () => {
      await mfkdf.setup.key([
        {
          type: 'password',
          id: 'password',
          data: Buffer.from('password', 'utf-8'),
          params: async () => {
            return {}
          },
          output: async () => {
            return {}
          }
        }
      ])
    })
    */

    test('valid', async () => {
      const { policy, key } = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('hello', { id: 'password1' }),
        await mfkdf.setup.factors.uuid({ id: 'uuid1' }),
        await mfkdf.setup.factors.uuid({ id: 'uuid2' })
      ], { threshold: 2 })

      policy.factors.length.should.equal(3)
      policy.threshold.should.equal(2)
    })

    test('id', async () => {
      await mfkdf.setup.key([
        await mfkdf.setup.factors.password('hello', { id: 'password1' }),
        await mfkdf.setup.factors.password('hello', { id: 'password1' })
      ]).should.be.rejectedWith(Mfkdf2Error.DuplicateFactorId)
    })
  })
});