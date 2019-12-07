import BN = require('bn.js')
import { expect } from 'chai'

import { GlobalHelper } from '../src/index'

describe('Global Helper Test', () => {
  it('should create a new BN', () => {
    expect(GlobalHelper.newBN(5, 2).eq(new BN(5, 2))).to.be.true
    expect(GlobalHelper.newBN(5, 10).eq(new BN(5, 10))).to.be.true
    expect(GlobalHelper.newBN(5).eq(new BN(5, 10))).to.be.true
  })

  it('should compute the number of bytes needed to store a number', () => {
    const numbers: number[] = [31, 32, 254, 255, 256, 511, 512]
    const bytes: number[] = [1, 1, 1, 1, 2, 2, 3]

    numbers.map((nr, idx) => {
      const numberOfBytes = GlobalHelper.getByteSizeForDecimalNumber(new BN(nr, 10))
      expect(numberOfBytes.eq(new BN(bytes[idx], 10))).to.be.true
    })
  })

  it('should generate random values', () => {
    for (let a = 0; a < 100; a++) {
      const rnd = GlobalHelper.getSecureRandomValue(new BN(5, 10)).toNumber()
      expect(rnd).to.be.at.least(1)
      expect(rnd).to.be.at.most(4)
    }
  })
})
