/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';

suite('setup/factors/password', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });
  /* invalid
  test('invalid/type', async () => {
    await mfkdf.setup.factors.password(12345).should.be.rejectedWith(TypeError)
    await mfkdf.setup.factors
      .password('password', { id: 12345 })
      .should.be.rejectedWith(TypeError)
  })
  */

  // test('invalid/range', async () => {
  //   await mfkdf.setup.factors.password('').should.be.rejectedWith(RangeError)
  //   await mfkdf.setup.factors
  //     .password('password', { id: '' })
  //     .should.be.rejectedWith(RangeError)
  // })

  test('valid', async () => {
    const factor = await mfkdf.setup.factors.password('hello')
    factor.type.should.equal('password')
    factor.data.toString('hex').should.equal('68656c6c6f')
    const params = await factor.params()
    params.should.deep.equal({})
  })
})
