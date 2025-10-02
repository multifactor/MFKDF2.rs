/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/ooba', () => {
  // Test RSA public key in JWK format
  const testKey = JSON.stringify({
    "key_ops": ["encrypt", "decrypt"],
    "ext": true,
    "alg": "RSA-OAEP-256",
    "kty": "RSA",
    "n": "1jR1L4H7Wov2W3XWlw1OII-fh_YuzfbZgpMCeSIPUd5oPvyvRf8nshkclQ9EQy6QlCZPX0HzCqkGokppxirKisyjfAlremiL8H60t2aapN_T3eClJ3KUxyEO1cejWoKejD86OtL_DWc04odInpcRmFgAF8mgjbEZRD0oSzaGlr70Ezi8p0yhpMTFM2Ltn0LG6SJ2_LGQwpEFNFf7790IoNpx8vKIZq0Ok1dGhC808f2t0ZhVFmxYnR-fp1jxd5B9nYDkjyJbWQK4vPlpAOgHw9v8G2Cg2X1TX2Ywr19tB249es2NlOYrFRQugzPyKfuVYxpFgoJfMuP83SPx-RvK6w",
    "e": "AQAB"
  });

  before(async () => {
    await uniffiInitAsync();
  });

  test('invalid/range - empty id', async () => {
    await mfkdf.setup.factors
      .ooba({ key: testKey, id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('invalid/range - invalid length', async () => {
    await mfkdf.setup.factors
      .ooba({ key: testKey, length: 0 })
      .should.be.rejectedWith(Mfkdf2Error.InvalidOobaLength)
    await mfkdf.setup.factors
      .ooba({ key: testKey, length: 33 })
      .should.be.rejectedWith(Mfkdf2Error.InvalidOobaLength)
  })

  test('invalid/range - missing key', async () => {
    await mfkdf.setup.factors
      .ooba({ key: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingOobaKey)
  })

  test('valid - with defaults', async () => {
    const factor = await mfkdf.setup.factors.ooba({ key: testKey })
    factor.type.should.equal('ooba')
    factor.id.should.equal('ooba')
    factor.data.should.have.length(32)
    const params = await factor.params()
    params.should.have.property('length', 6)
    params.should.have.property('key')
    params.should.have.property('params')
    params.should.have.property('next')
    params.should.have.property('pad')
  })

  test('valid - with length', async () => {
    const factor = await mfkdf.setup.factors.ooba({ key: testKey, length: 8 })
    factor.type.should.equal('ooba')
    const params = await factor.params()
    params.should.have.property('length', 8)
  })

  test('valid - with custom params', async () => {
    const customParams = JSON.stringify({ foo: 'bar' })
    const factor = await mfkdf.setup.factors.ooba({
      key: testKey,
      id: 'myooba',
      length: 8,
      params: customParams
    })
    factor.id.should.equal('myooba')
    factor.type.should.equal('ooba')
  })
})

