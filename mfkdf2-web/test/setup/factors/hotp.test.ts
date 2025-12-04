/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/hotp', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('invalid/range - empty id', async () => {
    await mfkdf.setup.factors
      .hotp({ id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('invalid/range - invalid digits', async () => {
    await mfkdf.setup.factors
      .hotp({ digits: 5 })
      .should.be.rejectedWith(Mfkdf2Error.InvalidHotpDigits)
    await mfkdf.setup.factors
      .hotp({ digits: 9 })
      .should.be.rejectedWith(Mfkdf2Error.InvalidHotpDigits)
  })

  test('valid - with defaults', async () => {
    const factor = await mfkdf.setup.factors.hotp()
    factor.type.should.equal('hotp')
    factor.data.should.have.length(4) // u32 bytes
    const params = await factor.params()
    params.should.have.property('hash')
    params.should.have.property('digits')
    params.should.have.property('pad')
    params.should.have.property('counter')
    params.should.have.property('offset')
  })

  test('valid - with secret', async () => {
    const secret = Buffer.from('hello world mfkdf2!!') // 20 bytes
    const factor = await mfkdf.setup.factors.hotp({ secret })
    factor.type.should.equal('hotp')
    factor.data.should.have.length(4)
  })

  test('valid - with options', async () => {
    const factor = await mfkdf.setup.factors.hotp({
      id: 'myhotp',
      digits: 8,
      issuer: 'TestCorp',
      label: 'test@example.com'
    })
    factor.id?.should.equal('myhotp')
    factor.type.should.equal('hotp')
    const output = await factor.output()
    output.should.have.property('issuer', 'TestCorp')
    output.should.have.property('label', 'test@example.com')
    output.should.have.property('digits', 8)
  })
})

