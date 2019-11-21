export {}
import { FFelGamal } from '../../src/index'
import { newBN } from '../../src/ff-elgamal/helper'
import { expect } from 'chai'

describe('Finite Field ElGamal System Setup', () => {
  it('combine public keys', () => {
    const sp: FFelGamal.SystemParameters = FFelGamal.SystemSetup.generateSystemParameters(11, 3)

    let shares = [newBN(1)]
    let product = 1
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)

    shares = [newBN(4), newBN(2)]
    product = 8
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)

    shares = [newBN(2), newBN(3), newBN(4)]
    product = 2
    expect(FFelGamal.SystemSetup.combinePublicKeys(sp, shares).toNumber()).to.eql(product)
  })
})
