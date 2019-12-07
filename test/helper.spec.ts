import BN = require('bn.js')
import { expect } from 'chai'

import { GlobalHelper } from '../src/index'

describe('Global Helper Test', () => {
  it('should create a new BN', () => {
    expect(GlobalHelper.newBN(5, 2).eq(new BN(5, 2))).to.be.true
    expect(GlobalHelper.newBN(5, 10).eq(new BN(5, 10))).to.be.true
    expect(GlobalHelper.newBN(5).eq(new BN(5, 10))).to.be.true
  })

  it('should invert BNs', () => {
    const base = 10
    const modulus = 4

    // inverse a mod modulus = c
    const tests = [
      { a: 0, c: 0 }, // none
      { a: 1, c: 1 },
      { a: 2, c: 1 }, // none
      { a: 3, c: 3 },
      { a: 4, c: 0 }, // none
      { a: 5, c: 1 },
      { a: 6, c: 1 }, // none
      { a: 7, c: 3 },
      { a: 8, c: 0 }, // none
      { a: 9, c: 1 },
    ]

    for (const test of tests) {
      const a = new BN(test.a, base)
      const c = new BN(test.c, base)
      const result = GlobalHelper.invmBN(a, new BN(modulus, base))

      const log = false
      log && console.log('a:', a.toNumber(), ', c:', c.toNumber(), 'res:', result.toNumber())
      expect(result.eq(c)).to.be.true
    }
  })

  it('should add BNs', () => {
    const base = 10
    const modulus = 4

    // a + b = c
    const tests = [
      { a: 0, b: 0, c: 0 },

      { a: 1, b: 0, c: 1 },
      { a: 1, b: 1, c: 2 },

      { a: 2, b: 0, c: 2 },
      { a: 2, b: 1, c: 3 },
      { a: 2, b: 2, c: 0 },

      { a: 3, b: 0, c: 3 },
      { a: 3, b: 1, c: 0 },
      { a: 3, b: 2, c: 1 },
      { a: 3, b: 3, c: 2 },

      { a: 4, b: 0, c: 0 },
      { a: 4, b: 1, c: 1 },
      { a: 4, b: 2, c: 2 },
      { a: 4, b: 3, c: 3 },
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

  it('should multiply BNs', () => {
    const base = 10
    const modulus = 4

    // a * b = c
    const tests = [
      { a: 0, b: 0, c: 0 },

      { a: 1, b: 0, c: 0 },
      { a: 1, b: 1, c: 1 },

      { a: 2, b: 0, c: 0 },
      { a: 2, b: 1, c: 2 },
      { a: 2, b: 2, c: 0 },

      { a: 3, b: 0, c: 0 },
      { a: 3, b: 1, c: 3 },
      { a: 3, b: 2, c: 2 },
      { a: 3, b: 3, c: 1 },

      { a: 4, b: 0, c: 0 },
      { a: 4, b: 1, c: 0 },
      { a: 4, b: 2, c: 0 },
      { a: 4, b: 3, c: 0 },
      { a: 4, b: 4, c: 0 },
    ]

    for (const test of tests) {
      const a = new BN(test.a, base)
      const b = new BN(test.b, base)
      const c = new BN(test.c, base)
      const result = GlobalHelper.mulBN(a, b, new BN(modulus, base))

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

  it('should divide BNs', () => {
    const base = 10
    const modulus = 4

    // a / b = c
    const tests = [
      { a: 0, b: 0, c: 0 }, // none

      { a: 1, b: 0, c: 0 }, // none
      { a: 1, b: 1, c: 1 },

      { a: 2, b: 0, c: 0 }, // none
      { a: 2, b: 1, c: 2 },
      { a: 2, b: 2, c: 2 },

      { a: 3, b: 0, c: 0 }, // none
      { a: 3, b: 1, c: 3 },
      { a: 3, b: 2, c: 3 },
      { a: 3, b: 3, c: 1 },

      { a: 4, b: 0, c: 0 }, // none
      { a: 4, b: 1, c: 0 }, // none
      { a: 4, b: 2, c: 0 }, // none
      { a: 4, b: 3, c: 0 }, // none
      { a: 4, b: 4, c: 0 }, // none
    ]

    for (const test of tests) {
      const a = new BN(test.a, base)
      const b = new BN(test.b, base)
      const c = new BN(test.c, base)
      const result = GlobalHelper.divBN(a, b, new BN(modulus, base))

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

  it('should exponentiate BNs', () => {
    const base = 10
    const modulus = 4

    // a^b = c
    const tests = [
      { a: 0, b: 0, c: 1 },

      { a: 1, b: 0, c: 1 },
      { a: 1, b: 1, c: 1 },

      { a: 2, b: 0, c: 1 },
      { a: 2, b: 1, c: 2 },
      { a: 2, b: 2, c: 0 },

      { a: 3, b: 0, c: 1 },
      { a: 3, b: 1, c: 3 },
      { a: 3, b: 2, c: 1 },
      { a: 3, b: 3, c: 3 },

      { a: 4, b: 0, c: 1 },
      { a: 4, b: 1, c: 0 },
      { a: 4, b: 2, c: 0 },
      { a: 4, b: 3, c: 0 },
      { a: 4, b: 4, c: 0 },
    ]

    for (const test of tests) {
      const a = new BN(test.a, base)
      const b = new BN(test.b, base)
      const c = new BN(test.c, base)
      const result = GlobalHelper.powBN(a, b, new BN(modulus, base))

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

  // -------------------------------------------------
  // timing safe equality
  // -------------------------------------------------
  const timingLog = false

  // Returns the mean of an array
  const mean = (array: number[]): number => {
    return array.reduce((sum, val) => sum + val, 0) / array.length
  }

  // Returns the sample standard deviation of an array
  const standardDeviation = (array: number[]): number => {
    const arrMean = mean(array)
    const total = array.reduce((sum, val) => sum + Math.pow(val - arrMean, 2), 0)
    return Math.sqrt(total / (array.length - 1))
  }

  // Returns the common standard deviation of two arrays
  const combinedStandardDeviation = (arr1: number[], arr2: number[]): number => {
    const sum1 = Math.pow(standardDeviation(arr1), 2) * (arr1.length - 1)
    const sum2 = Math.pow(standardDeviation(arr2), 2) * (arr2.length - 1)
    return Math.sqrt((sum1 + sum2) / (arr1.length + arr2.length - 2))
  }

  // Filter large outliers from an array. A 'large outlier' is a value that is at
  // least 50 times larger than the mean. This prevents the tests from failing
  // due to the standard deviation increase when a function unexpectedly takes
  // a very long time to execute.
  const filterOutliers = (array: number[]): number[] => {
    const arrMean = mean(array)
    return array.filter(value => value / arrMean < 50)
  }

  const safeEqualityCheck = (a: Buffer, b: Buffer, equalInputs: boolean): number => {
    const startTime = process.hrtime()
    const equalityCheck: boolean = GlobalHelper.timingSafeEqual(a, b)
    const endTime = process.hrtime(startTime)

    if (equalInputs) {
      expect(equalityCheck).to.be.true
    } else {
      expect(equalityCheck).to.be.false
    }

    const diff = (1e9 * endTime[0] + endTime[1]) / 1e9
    //console.log('execution A. time:', diff)
    return diff
  }

  const unsafeEqualityCheck = (a: Buffer, b: Buffer, equalInputs: boolean): number => {
    const startTime = process.hrtime()
    const equalityCheck: boolean = a.equals(b)
    const endTime = process.hrtime(startTime)

    if (equalInputs) {
      expect(equalityCheck).to.be.true
    } else {
      expect(equalityCheck).to.be.false
    }

    const diff = (1e9 * endTime[0] + endTime[1]) / 1e9
    //console.log('execution A. time:', diff)
    return diff
  }

  const benchmark = (
    equalityCheck: (a: Buffer, b: Buffer, equalInputs: boolean) => number
  ): number => {
    const numberOfTrials = 10000
    const bufferSize = 64

    const equalResults: number[] = Array(numberOfTrials)
    const unequalResults: number[] = Array(numberOfTrials)

    for (let i = 0; i < numberOfTrials; i++) {
      if (i % 2 == 0) {
        const bufferA1: Buffer = Buffer.alloc(bufferSize, 'A', 'utf8')
        const bufferB: Buffer = Buffer.alloc(bufferSize, 'B', 'utf8')
        const bufferA2: Buffer = Buffer.alloc(bufferSize, 'A', 'utf8')
        const bufferC: Buffer = Buffer.alloc(bufferSize, 'C', 'utf8')

        equalResults[i] = equalityCheck(bufferA1, bufferA2, true)
        unequalResults[i] = equalityCheck(bufferB, bufferC, false)
      } else {
        // Swap the order of the benchmarks every second iteration, to avoid any patterns caused by memory usage.
        const bufferA2: Buffer = Buffer.alloc(bufferSize, 'A', 'utf8')
        const bufferC: Buffer = Buffer.alloc(bufferSize, 'C', 'utf8')
        const bufferA1: Buffer = Buffer.alloc(bufferSize, 'A', 'utf8')
        const bufferB: Buffer = Buffer.alloc(bufferSize, 'B', 'utf8')

        equalResults[i] = equalityCheck(bufferA1, bufferA2, true)
        unequalResults[i] = equalityCheck(bufferB, bufferC, false)
      }
    }

    const equalBenches = filterOutliers(equalResults)
    const unequalBenches = filterOutliers(unequalResults)

    // Use a two-sample t-test to determine whether the timing difference between
    // the benchmarks is statistically significant.
    // https://wikipedia.org/wiki/Student%27s_t-test#Independent_two-sample_t-test

    const equalMean = mean(equalBenches)
    const unequalMean = mean(unequalBenches)

    const equalLen = equalBenches.length
    const unequalLen = unequalBenches.length

    const combinedStd = combinedStandardDeviation(equalBenches, unequalBenches)
    const standardErr = combinedStd * Math.sqrt(1 / equalLen + 1 / unequalLen)

    return (equalMean - unequalMean) / standardErr
  }

  it('should perform timing safe equality checks - benchmark', () => {
    // t_(0.99995, ∞)
    // i.e. If a given comparison function is indeed timing-safe, the t-test result
    // has a 99.99% chance to be below this threshold. Unfortunately, this means
    // that this test will be a bit flakey and will fail 0.01% of the time even if
    // crypto.timingSafeEqual is working properly.
    // t-table ref: http://www.sjsu.edu/faculty/gerstman/StatPrimer/t-table.pdf
    // Note that in reality there are roughly `2 * numTrials - 2` degrees of
    // freedom, not ∞. However, assuming `numTrials` is large, this doesn't
    // significantly affect the threshold.
    const T_THRESHOLD = 3.892

    const tValueSafe = benchmark(safeEqualityCheck)
    timingLog && console.log('Safe T-Value:\t', Math.abs(tValueSafe))
    expect(Math.abs(tValueSafe) < T_THRESHOLD).to.be.true

    // As a sanity check to make sure the statistical tests are working, run the
    // same benchmarks again, this time with an unsafe comparison function. In this
    // case the t-value should be above the threshold.
    // const unsafeCompare = (bufA, bufB) => bufA.equals(bufB)
    // const t2 = getTValue(unsafeCompare)
    // t.ok(
    //   Math.abs(t2) > T_THRESHOLD,
    //   `Buffer#equals should leak information from its execution time (t=${t2})`
    // )
    const tValueUnsafe = benchmark(unsafeEqualityCheck)
    timingLog && console.log('Unsafe T-Value:\t', Math.abs(tValueUnsafe))
  })
})
