/* eslint no-unused-expressions: "off" */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
chai.should();

import { suite, test } from 'mocha';
import mfkdf, { uniffiInitAsync } from '../../../src/api';
import { Mfkdf2Error } from '../../../src';

suite('derive/factors/password', () => {
  // Initialize UniFFI once before all tests
  before(async () => {
    await uniffiInitAsync();
  });

  /* invalid test
  test('invalid/type', () => {
    (() => {
      mfkdf.derive.factors.password(12345)
    }).should.throw(TypeError)
  })
  */

  test('invalid/type', async () => {
    await mfkdf.derive.factors
      .password('')
      .should.be.rejectedWith(Mfkdf2Error.PasswordEmpty)
  })
})
