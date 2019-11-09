// check if a given number is prime
export const isPrime = (num: number) => {
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
export const getQofP = (p: any) => (p > 1 ? (p - 1) / 2 : -1)

// q is valid if it is prime
export const isQValid = (q: any) => (q > 1 ? isPrime(q) : false)

// g is valid if:
// - g != 1
// - q != q
// - g^q mod p == 1
export const isGValid = (g: any, p: any) => {
  return g !== 1 && g !== getQofP(p) && g ** getQofP(p) % p === 1
}

// get all primes that have a q = (p-1)/2 that is prime given a list of primes
export const getPCandidates = (primes: any) =>
  primes.reduce((previous: any, current: any) => {
    return isQValid(getQofP(current)) ? [...previous, current] : previous
  }, [])

// get all generators g of q given a prime p
export const getGCandidates = (p: any) =>
  getPrimitiveRoots(getQofP(p)).reduce((previous: any, current: any) => {
    return isGValid(current, p) ? [...previous, current] : previous
  }, [])

import crypto = require('crypto')
import BN = require('bn.js')

export const getSecureRandomValue = (q: BN): BN => {
  const one = new BN(1, 10)

  // TODO: Fix upper limit to q-1
  const UPPER_BOUND_RANDOM: BN = q.sub(one)
  const RAND_SIZE_BYTES = 1

  let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
  let randomValue = new BN(randomBytes)

  // ensure that the random value is in range [1,n-1]
  while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(one))) {
    randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    randomValue = new BN(randomBytes, 'hex')
  }
  return randomValue
}

export const newBN = (num: number, base: number = 10): BN => new BN(num, base)
export const BNadd = (a: BN, b: BN, modulus: BN) => a.add(b).mod(modulus)
export const BNmul = (a: BN, b: BN, modulus: BN) => a.mul(b).mod(modulus)
export const BNpow = (a: BN, b: BN, modulus: BN) => a.pow(b).mod(modulus)
export const BNinvm = (a: BN, modulus: BN) => a.invm(modulus)
export const BNdiv = (a: BN, b: BN, modulus: BN) => BNmul(a, BNinvm(b, modulus), modulus)
