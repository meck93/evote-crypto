import BN = require('bn.js')

import { expect } from 'chai'
import { GlobalHelper, FFelGamal } from '../../src/index'

describe('Finite Field ElGamal System Setup', () => {
  it('should generate the system parameters', () => {
    const sp: FFelGamal.SystemParameters = FFelGamal.SystemSetup.generateSystemParameters(11, 3)
    const expectedSP: FFelGamal.SystemParameters = {
      p: new BN(11, 10),
      q: new BN(5, 10),
      g: new BN(3, 10),
    }

    expect(sp.p.eq(expectedSP.p)).to.be.true
    expect(sp.q.eq(expectedSP.q)).to.be.true
    expect(sp.g.eq(expectedSP.g)).to.be.true
  })

  it('should generate a key pair', () => {
    const sp: FFelGamal.SystemParameters = FFelGamal.SystemSetup.generateSystemParameters(11, 3)

    for (let i = 0; i < 100; i++) {
      const kp: FFelGamal.KeyPair = FFelGamal.SystemSetup.generateKeyPair(sp)

      // sk: 1 <= sk < q
      const skLowerBound = new BN(1, 10)
      const skUpperBound = new BN(sp.q, 10).sub(new BN(1, 10))
      expect(kp.sk.gte(skLowerBound)).to.be.true
      expect(kp.sk.lte(skUpperBound)).to.be.true

      // h == g^sk mod p
      expect(kp.h.eq(sp.g.pow(kp.sk).mod(sp.p)))
    }
  })

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
