/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src/generated/web/mfkdf2.js';

suite('setup/factors/question', () => {
  before(async () => {
    await uniffiInitAsync();
  });

  test('invalid/range - empty id', async () => {
    await mfkdf.setup.factors
      .question('answer', { id: '' })
      .should.be.rejectedWith(Mfkdf2Error.MissingFactorId)
  })

  test('invalid/range - empty answer', async () => {
    await mfkdf.setup.factors
      .question('')
      .should.be.rejectedWith(Mfkdf2Error.AnswerEmpty)
  })

  test('valid - with defaults', async () => {
    const factor = await mfkdf.setup.factors.question('Paris')
    factor.type.should.equal('question')
    factor.id.should.equal('question')
    // Answer is normalized: lowercase, alphanumeric only
    factor.data.toString().should.equal('paris')
    const params = await factor.params()
    params.should.have.property('question', '')
  })

  test('valid - with question', async () => {
    const factor = await mfkdf.setup.factors.question('Paris', {
      question: 'What is the capital of France?'
    })
    factor.type.should.equal('question')
    const params = await factor.params()
    params.should.have.property('question', 'What is the capital of France?')
  })

  test('valid - answer normalization', async () => {
    const factor = await mfkdf.setup.factors.question('  My Answer is... Test 123!  ')
    factor.data.toString().should.equal('myansweristest123')
  })

  test('valid - with id', async () => {
    const factor = await mfkdf.setup.factors.question('blue', {
      id: 'color',
      question: 'Favorite color?'
    })
    factor.id.should.equal('color')
    const output = await factor.output()
    output.should.have.property('strength')
  })
})

