import BN = require('bn.js')
import crypto = require('crypto')

// check if a given number is prime
export const isPrime = (num: number): boolean => {
  for (let i = 2; i <= Math.sqrt(num); i++) {
    if (Math.floor(num / i) == num / i) {
      return false
    }
  }
  return true
}

// get all primitive roots of a given number
// only works for prime numbers
// TODO: implement for non-prime numbers
export const getPrimitiveRoots = (n: number): number[] => {
  if (!isPrime(n)) {
    return []
  }

  // source: https://asecuritysite.com/encryption/pickg
  const g: number[] = []
  for (let i = 1; i < n; i++) {
    let exp = 1
    let next = i % n

    while (next !== 1) {
      next = (next * i) % n
      exp += 1
    }

    if (exp === n - 1) {
      g.push(i)
    }
  }

  return g
}

// calculate q given p (for p < 2)
// TODO: maybe check if p is actually prime
export const getQofP = (p: number): number => (p > 1 ? (p - 1) / 2 : -1)

// q is valid if it is prime
export const isQValid = (q: number): boolean => (q > 1 ? isPrime(q) : false)

// g is valid if:
// - g != 1
// - q != q
// - g^q mod p == 1
export const isGValid = (g: number, p: number): boolean => {
  return g !== 1 && g !== getQofP(p) && g ** getQofP(p) % p === 1
}

// get all primes that have a q = (p-1)/2 that is prime given a list of primes
export const getPCandidates = (primes: number[]): number[] =>
  primes.reduce((previous: number[], current: number) => {
    return isQValid(getQofP(current)) ? [...previous, current] : previous
  }, [])

// get all generators g of q given a prime p
export const getGCandidates = (p: number): number[] =>
  getPrimitiveRoots(getQofP(p)).reduce((previous: number[], current: number) => {
    return isGValid(current, p) ? [...previous, current] : previous
  }, [])

// Computes the required number of bytes to store a decimal
export const getByteSizeForDecimalNumber = (q: BN): number => {
  const modulus: BN = q.mod(new BN(256, 10))
  const smallerHalf: boolean = modulus.lt(new BN(128, 10))
  const result: number = q.divRound(new BN(256, 10)).toNumber()
  return smallerHalf ? result + 1 : result
}

export const getSecureRandomValue = (q: BN): BN => {
  const one = new BN(1, 10)
  const UPPER_BOUND_RANDOM: BN = q.sub(one)
  const byteSize = getByteSizeForDecimalNumber(q)

  let randomBytes: Buffer = crypto.randomBytes(byteSize)
  let randomValue: BN = new BN(randomBytes)

  // ensure that the random value is in range [1,n-1]
  while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(one))) {
    randomBytes = crypto.randomBytes(byteSize)
    randomValue = new BN(randomBytes)
  }
  return randomValue
}

export const newBN = (num: number, base = 10): BN => new BN(num, base)
export const BNadd = (a: BN, b: BN, modulus: BN): BN => a.add(b).mod(modulus)
export const BNsub = (a: BN, b: BN, modulus: BN): BN => a.sub(b).mod(modulus)
export const BNmul = (a: BN, b: BN, modulus: BN): BN => a.mul(b).mod(modulus)
export const BNpow = (a: BN, b: BN, modulus: BN): BN => a.pow(b).mod(modulus)
export const BNinvm = (a: BN, modulus: BN): BN => a.invm(modulus)
export const BNdiv = (a: BN, b: BN, modulus: BN): BN => BNmul(a, BNinvm(b, modulus), modulus)

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
