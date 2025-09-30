/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/uuid', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  test('invalid/type', async () => {
    await mfkdf.setup.factors
      .uuid({ uuid: 12345 as any })
      .should.be.rejectedWith("Failed to convert arg")
    await mfkdf.setup.factors
      .uuid({ uuid: 'hello' })
      .should.be.rejectedWith("Failed to convert arg")
    // TODO: recheck this
    // await mfkdf.setup.factors
    //   .uuid({ id: 12345 as any })
    //   .should.be.rejectedWith(TypeError)
  })

  test('invalid/range', async () => {
    await mfkdf.setup.factors
      .uuid({ id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('valid', async () => {
    const factor = await mfkdf.setup.factors.uuid({
      uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b'
    })
    factor.type.should.equal('uuid')
    factor.data
      .toString('hex')
      .should.equal('6ec0bd7f11c043da975e2a8ad9ebae0b')
    const params = await factor.params()
    params.should.deep.equal({})
  })

  test('random', async () => {
    const factor = await mfkdf.setup.factors.uuid({})
    factor.type.should.equal('uuid')
    const output = await factor.output()
    factor.data.toString('hex').should.equal(output.uuid.replaceAll('-', ''))
    const params = await factor.params()
    params.should.deep.equal({})
  })
})

