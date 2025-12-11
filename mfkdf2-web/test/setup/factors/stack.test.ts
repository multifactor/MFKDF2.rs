/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/stack', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('invalid/range - empty id', async () => {
    const factor1 = await mfkdf.setup.factors.password('password1', { id: 'pwd1' })
    await mfkdf.setup.factors
      .stack([factor1], { id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('invalid/range - no factors', async () => {
    await mfkdf.setup.factors
      .stack([], { id: 'mystack' })
      .should.be.rejected
  })

  test('valid - with single factor', async () => {
    const factor1 = await mfkdf.setup.factors.password('password1', { id: 'pwd1' })
    const stackFactor = await mfkdf.setup.factors.stack([factor1])
    stackFactor.type.should.equal('stack')
    stackFactor.id?.should.equal('stack')
    stackFactor.should.have.property('data')
    const params = await stackFactor.params()
    params.should.have.property('threshold', 1)
  })

  test('valid - with multiple factors', async () => {
    const factor1 = await mfkdf.setup.factors.password('password1', { id: 'pwd1' })
    const factor2 = await mfkdf.setup.factors.password('password2', { id: 'pwd2' })
    const stackFactor = await mfkdf.setup.factors.stack([factor1, factor2], {
      id: 'mystack'
    })
    stackFactor.type.should.equal('stack')
    stackFactor.id?.should.equal('mystack')
    const params = await stackFactor.params()
    params.should.have.property('threshold', 2)
    params.should.have.property('factors')
  })

  test('valid - with threshold', async () => {
    const factor1 = await mfkdf.setup.factors.password('password1', { id: 'pwd1' })
    const factor2 = await mfkdf.setup.factors.password('password2', { id: 'pwd2' })
    const factor3 = await mfkdf.setup.factors.password('password3', { id: 'pwd3' })
    const stackFactor = await mfkdf.setup.factors.stack([factor1, factor2, factor3], {
      id: 'mystack',
      threshold: 2
    })
    stackFactor.type.should.equal('stack')
    const params = await stackFactor.params()
    params.should.have.property('threshold', 2)
  })

  test('valid - with salt', async () => {
    const factor1 = await mfkdf.setup.factors.password('password1', { id: 'pwd1' })
    const salt = new Uint8Array(32)
    for (let i = 0; i < 32; i++) {
      salt[i] = i
    }
    const stackFactor = await mfkdf.setup.factors.stack([factor1], {
      salt: salt.buffer
    })
    stackFactor.type.should.equal('stack')
    const output = await stackFactor.output()
    output.should.have.property('policy')
  })
})

