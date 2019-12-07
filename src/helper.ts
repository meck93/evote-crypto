import BN = require('bn.js')
import crypto = require('crypto')

export const newBN = (n: number, base = 10): BN => new BN(n, base)
export const invmBN = (a: BN, modulus: BN): BN => a.invm(modulus)
export const addBN = (a: BN, b: BN, modulus: BN): BN => a.add(b).mod(modulus)
export const subBN = (a: BN, b: BN, modulus: BN): BN => a.sub(b).mod(modulus)
export const mulBN = (a: BN, b: BN, modulus: BN): BN => a.mul(b).mod(modulus)

// compute the required number of bytes to store a decimal
export const getByteSizeForDecimalNumber = (n: BN): BN => {
  const modulus: BN = n.mod(new BN(256, 10))
  const smallerHalf: boolean = modulus.lt(new BN(128, 10))
  const result: BN = n.divRound(new BN(256, 10))
  return smallerHalf ? result.add(new BN(1, 10)) : result
}

export const getSecureRandomValue = (n: BN): BN => {
  const ONE: BN = new BN(1, 10)
  const UPPER_BOUND_RANDOM: BN = n.sub(ONE)
  const BYTE_SIZE: BN = getByteSizeForDecimalNumber(n)

  let byteSize: number
  try {
    byteSize = BYTE_SIZE.toNumber()
  } catch {
    // https://www.ecma-international.org/ecma-262/5.1/#sec-8.5
    // used for large numbers from EC
    byteSize = 32
  }

  let randomBytes: Buffer = crypto.randomBytes(byteSize)
  let randomValue: BN = new BN(randomBytes)

  // ensure that the random value is in range [1, n-1]
  while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(ONE))) {
    randomBytes = crypto.randomBytes(byteSize)
    randomValue = new BN(randomBytes)
  }
  return randomValue
}
