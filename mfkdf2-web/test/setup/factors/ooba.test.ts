/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';
import crypto from 'crypto';

suite('setup/factors/ooba', () => {
  let keyPair: crypto.webcrypto.CryptoKeyPair;
  before(async () => {
    await uniffiInitAsync();
    keyPair = await crypto.webcrypto.subtle.generateKey(
      {
        hash: 'SHA-256',
        modulusLength: 2048,
        name: 'RSA-OAEP',
        publicExponent: new Uint8Array([1, 0, 1])
      },
      true,
      ['encrypt', 'decrypt']
    );
  });

  test('invalid/range - empty id', async () => {

    await mfkdf.setup.factors
      .ooba({ key: keyPair.publicKey, id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('invalid/range - invalid length', async () => {
    await mfkdf.setup.factors
      .ooba({ key: keyPair.publicKey, length: 0 })
      .should.be.rejectedWith(Mfkdf2Error.InvalidOobaLength)
    await mfkdf.setup.factors
      .ooba({ key: keyPair.publicKey, length: 33 })
      .should.be.rejectedWith(Mfkdf2Error.InvalidOobaLength)
  })

  test('invalid/range - missing key', async () => {
    await mfkdf.setup.factors
      .ooba({})
      .should.be.rejectedWith(Mfkdf2Error.MissingOobaKey)
  })

  test('valid - with defaults', async () => {
    const factor = await mfkdf.setup.factors.ooba({ key: keyPair.publicKey })
    factor.type.should.equal('ooba')
    factor.id?.should.equal('ooba')
    factor.data.should.have.length(32)
    const params = await factor.params()
    params.should.have.property('length', 6)
    params.should.have.property('key')
    params.should.have.property('params')
    params.should.have.property('next')
    params.should.have.property('pad')
  })

  test('valid - with length', async () => {
    const factor = await mfkdf.setup.factors.ooba({ key: keyPair.publicKey, length: 8 })
    factor.type.should.equal('ooba')
    const params = await factor.params()
    params.should.have.property('length', 8)
  })

  test('valid - with custom params', async () => {
    const customParams = { foo: 'bar' }
    const factor = await mfkdf.setup.factors.ooba({
      key: keyPair.publicKey,
      id: 'myooba',
      length: 8,
      params: customParams
    })
    factor.id?.should.equal('myooba')
    factor.type.should.equal('ooba')
  })
})

