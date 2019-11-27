import { expect } from 'chai'
import { FFelGamal } from '../../src/index'

describe('Finite Field ElGamal System Setup', () => {
  it('combine public keys', () => {
    const sp: FFelGamal.SystemParameters = FFelGamal.SystemSetup.generateSystemParameters(11, 3)

    let shares = [FFelGamal.Helper.newBN(1)]
    let product = 1
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)

    shares = [FFelGamal.Helper.newBN(4), FFelGamal.Helper.newBN(2)]
    product = 8
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)

    shares = [FFelGamal.Helper.newBN(2), FFelGamal.Helper.newBN(3), FFelGamal.Helper.newBN(4)]
    product = 2
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)
  })
})
