/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/totp', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('invalid/range - empty id', async () => {
    await mfkdf.setup.factors
      .totp({ id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('invalid/range - invalid digits', async () => {
    await mfkdf.setup.factors
      .totp({ digits: 5 })
      .should.be.rejectedWith(Mfkdf2Error.InvalidTotpDigits)
    await mfkdf.setup.factors
      .totp({ digits: 9 })
      .should.be.rejectedWith(Mfkdf2Error.InvalidTotpDigits)
  })

  test('valid - with defaults', async () => {
    const factor = await mfkdf.setup.factors.totp()
    factor.type.should.equal('totp')
    factor.data.should.have.length(4) // u32 bytes
    const params = await factor.params()
    params.should.have.property('hash')
    params.should.have.property('digits')
    params.should.have.property('pad')
    params.should.have.property('start')
    params.should.have.property('step')
    params.should.have.property('window')
    params.should.have.property('offsets')
  })

  test('valid - with secret', async () => {
    const secret = Buffer.from('my-super-secret-1234') // 20 bytes
    const factor = await mfkdf.setup.factors.totp({ secret })
    factor.type.should.equal('totp')
    factor.data.should.have.length(4)
  })

  test('valid - with options', async () => {
    const factor = await mfkdf.setup.factors.totp({
      id: 'mytotp',
      digits: 8,
      issuer: 'TestCorp',
      label: 'test@example.com',
      step: 60
    })
    factor.id?.should.equal('mytotp')
    factor.type.should.equal('totp')
    const output = await factor.output()
    output.should.have.property('issuer', 'TestCorp')
    output.should.have.property('label', 'test@example.com')
    output.should.have.property('digits', 8)
    output.should.have.property('period', 60)
  })
})

