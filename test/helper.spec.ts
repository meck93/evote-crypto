import BN = require('bn.js')
import { expect } from 'chai'

import { GlobalHelper } from '../src/index'

describe('Global Helper Test', () => {
  it('should create a new BN', () => {
    expect(GlobalHelper.newBN(5, 2).eq(new BN(5, 2))).to.be.true
    expect(GlobalHelper.newBN(5, 10).eq(new BN(5, 10))).to.be.true
    expect(GlobalHelper.newBN(5).eq(new BN(5, 10))).to.be.true
  })

  it('should add BNs', () => {
    const base = 10
    const modulus = 4

    // a + b = c
    const tests = [
      { a: 0, b: 0, c: 0 },
      { a: 0, b: 1, c: 1 },
      { a: 1, b: 1, c: 2 },
      { a: 1, b: 2, c: 3 },
      { a: 2, b: 2, c: 0 },
      { a: 2, b: 3, c: 1 },
      { a: 3, b: 3, c: 2 },
      { a: 3, b: 4, c: 3 },
      { a: 4, b: 4, c: 0 },
    ]

    for (const test of tests) {
      const a = new BN(test.a, base)
      const b = new BN(test.b, base)
      const c = new BN(test.c, base)
      const result = GlobalHelper.addBN(a, b, new BN(modulus, base))

      const log = false
      log &&
        console.log(
          'a:',
          a.toNumber(),
          ', b:',
          b.toNumber(),
          ', c:',
          c.toNumber(),
          'res:',
          result.toNumber()
        )
      expect(result.eq(c)).to.be.true
    }
  })

  it('should subtract BNs', () => {
    const base = 10
    const modulus = 4

    // a - b = c
    const tests = [
      { a: 0, b: 0, c: 0 },

      { a: 1, b: 0, c: 1 },
      { a: 1, b: 1, c: 0 },

      { a: 2, b: 0, c: 2 },
      { a: 2, b: 1, c: 1 },
      { a: 2, b: 2, c: 0 },

      { a: 3, b: 0, c: 3 },
      { a: 3, b: 1, c: 2 },
      { a: 3, b: 2, c: 1 },
      { a: 3, b: 3, c: 0 },

      { a: 4, b: 0, c: 0 },
      { a: 4, b: 1, c: 3 },
      { a: 4, b: 2, c: 2 },
      { a: 4, b: 3, c: 1 },
      { a: 4, b: 4, c: 0 },
    ]

    for (const test of tests) {
      const a = new BN(test.a, base)
      const b = new BN(test.b, base)
      const c = new BN(test.c, base)
      const result = GlobalHelper.subBN(a, b, new BN(modulus, base))

      const log = false
      log &&
        console.log(
          'a:',
          a.toNumber(),
          ', b:',
          b.toNumber(),
          ', c:',
          c.toNumber(),
          'res:',
          result.toNumber()
        )
      expect(result.eq(c)).to.be.true
    }
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
