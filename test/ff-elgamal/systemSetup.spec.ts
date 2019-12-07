import { expect } from 'chai'
import { GlobalHelper, FFelGamal } from '../../src/index'

describe('Finite Field ElGamal System Setup', () => {
  it('combine public keys', () => {
    const sp: FFelGamal.SystemParameters = FFelGamal.SystemSetup.generateSystemParameters(11, 3)

    let shares = [GlobalHelper.newBN(1)]
    let product = 1
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)

    shares = [GlobalHelper.newBN(4), GlobalHelper.newBN(2)]
    product = 8
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)

    shares = [GlobalHelper.newBN(2), GlobalHelper.newBN(3), GlobalHelper.newBN(4)]
    product = 2
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)
  })
})
