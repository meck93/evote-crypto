import BN = require('bn.js')
import crypto = require('crypto')

export const newBN = (n: number, base = 10): BN => new BN(n, base)
export const invmBN = (a: BN, modulus: BN): BN => a.invm(modulus)
export const addBN = (a: BN, b: BN, modulus: BN): BN => a.add(b).mod(modulus)
export const subBN = (a: BN, b: BN, modulus: BN): BN => a.sub(b).mod(modulus)
export const mulBN = (a: BN, b: BN, modulus: BN): BN => a.mul(b).mod(modulus)
export const divBN = (a: BN, b: BN, modulus: BN): BN => mulBN(a, invmBN(b, modulus), modulus)
export const powBN = (a: BN, b: BN, modulus: BN): BN => a.pow(b).mod(modulus)

// compute the required number of bytes to store a decimal
export const getByteSizeForDecimalNumber = (n: BN): BN => {
  const modulus: BN = n.mod(new BN(256, 10))
  const smallerHalf: boolean = modulus.lt(new BN(128, 10))
  const result: BN = n.divRound(new BN(256, 10))
  return smallerHalf ? result.add(new BN(1, 10)) : result
}

// get a secure random value x: 0 < x < n
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

export const timingSafeEqual = (a: Buffer, b: Buffer): boolean => {
  if (!Buffer.isBuffer(a)) {
    throw new TypeError('First argument must be a buffer')
  }
  if (!Buffer.isBuffer(b)) {
    throw new TypeError('Second argument must be a buffer')
  }
  if (a.length !== b.length) {
    throw new TypeError('Input buffers must have the same length')
  }
  let out = 0
  for (let i = 0; i < a.length; i++) {
    out |= a[i] ^ b[i]
  }
  return out === 0
}
