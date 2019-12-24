import { expect } from 'chai'
import * as Models from '../../src/ff-elgamal/models'
import BN from 'bn.js'

describe('Model Typechecking Test', () => {
  it('SystemParameters Type Test', () => {
    // invalid systemsparameter object: incorrect variables, correct types
    const testObject0 = { a: new BN(23), b: new BN(11), c: new BN(3) }
    const check0 = Models.isSystemParameters(testObject0)
    expect(check0).to.be.false

    // invalid systemsparameter object: correct variables, incorrect types
    const testObject1 = { p: 23, q: 11, g: 3 }
    const check1 = Models.isSystemParameters(testObject1)
    expect(check1).to.be.false

    // valid creation of systems parameter object
    const testObject2 = { p: new BN(23), q: new BN(11), g: new BN(3) }
    const check2 = Models.isSystemParameters(testObject2)
    expect(check2).to.be.true
  })

  it('KeyPair Type Test', () => {
    // invalid keypair object: correct variables, wrong type
    const testObject1 = { h: new BN(3), sk: 2 }
    const check1 = Models.isKeyPair(testObject1)
    expect(check1).to.be.false

    // invalid keypair object: incorrect variables, correct type
    const testObject2 = { h: new BN(3), p: new BN(2) }
    const check2 = Models.isKeyPair(testObject2)
    expect(check2).to.be.false

    // valid creation of keypair object
    const testObject3 = { h: new BN(3), sk: new BN(2) }
    const check3 = Models.isKeyPair(testObject3)
    expect(check3).to.be.true
  })

  it('Cipher Type Test', () => {
    // invalid cipher object: correct variables, wrong type
    const testObject1 = { a: 3, b: 2 }
    const check1 = Models.isCipher(testObject1)
    expect(check1).to.be.false

    // invalid cipher object: incorrect variables, correct type
    const testObject2 = { h: new BN(3), p: new BN(2) }
    const check2 = Models.isCipher(testObject2)
    expect(check2).to.be.false

    // valid creation of cipher object
    const testObject3 = { a: new BN(3), b: new BN(2) }
    const check3 = Models.isCipher(testObject3)
    expect(check3).to.be.true

    // valid creation of cipher object: including r
    const testObject4 = { a: new BN(3), b: new BN(2), r: new BN(1) }
    const check4 = Models.isCipher(testObject4)
    expect(check4).to.be.true

    // invalid cipher object: a,b correct -> r wrong
    const testObject5 = { a: new BN(3), b: new BN(2), r: 1 }
    const check5 = Models.isCipher(testObject5)
    expect(check5).to.be.false
  })
})
