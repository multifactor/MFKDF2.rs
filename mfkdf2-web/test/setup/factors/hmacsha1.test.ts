/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/hmacsha1', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('invalid/range - empty id', async () => {
    await mfkdf.setup.factors
      .hmacsha1({ id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('valid - with defaults', async () => {
    const factor = await mfkdf.setup.factors.hmacsha1()
    factor.type.should.equal('hmacsha1')
    factor.data.should.have.length(32) // 20 bytes + 12 bytes of padding
    factor.id?.should.equal('hmacsha1')
    const params = await factor.params()
    params.should.have.property('challenge')
    params.should.have.property('pad')
  })

  test('valid - with secret', async () => {
    const secret = Buffer.from([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14
    ])
    const factor = await mfkdf.setup.factors.hmacsha1({ secret })
    factor.type.should.equal('hmacsha1')
    Buffer.from(factor.data).subarray(0, 20).should.deep.equal(secret)
  })

  test('valid - with id', async () => {
    const factor = await mfkdf.setup.factors.hmacsha1({ id: 'myhmac' })
    factor.id?.should.equal('myhmac')
    factor.type.should.equal('hmacsha1')
    const output = await factor.output()
    output.should.have.property('secret')
  })
})

