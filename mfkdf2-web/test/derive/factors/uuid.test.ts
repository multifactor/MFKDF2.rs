/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';

suite('derive/factors/uuid', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  /* invalid test
  test('invalid/type', () => {
    (() => {
      mfkdf.derive.factors.uuid(12345)
    }).should.throw(TypeError)
  })
  */

  test('invalid/type', async () => {
    await mfkdf.derive.factors
      .uuid('')
      .should.be.rejectedWith('Failed to convert arg')
  })
})

