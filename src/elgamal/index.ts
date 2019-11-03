import { PublicKey } from './models'
import { Cipher } from '../models'

const BN = require('bn.js')
const random = require('random')
// const crypto = require('crypto')

// export const getSecureRandomValue = (): any => {
//   const RAND_SIZE_BYTES = 32

//   // TODO: Fix upper limit to p-2
//   const UPPER_BOUND_RANDOM = null

//   let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
//   let randomValue = new BN(randomBytes)

//   // ensure that the random value is in range [1,n-1]
//   while (!randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(1)) {
//     randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
//     randomValue = new BN(randomBytes, 'hex')
//   }
//   return randomValue
// }

// calculate q given p
const getQofP = (p: any) => (p - 1) / 2

// get all primes that have a q = (p-1)/2
const getPCandidates = (primes: any) =>
  primes.reduce((previous: any, current: any) => {
    return primes.includes(getQofP(current)) ? [...previous, current] : previous
  }, [])

// get all generators g given a prime
const getGCandidates = (prime: any) =>
  Array.from(Array(prime).keys()).reduce((previous: any, current: any) => {
    return Math.pow(current, getQofP(prime)) % prime === 1 ? [...previous, current] : previous
  }, [])

const primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

export const findSuitableInputs = () => {
  const prime = 11
  console.log('p', prime)
  console.log('p candidates', getPCandidates(primes))
  console.log('g candidates', getGCandidates(prime))
  console.log()
}

export const generateKeys = (_p: number, _q: number, _g: number): [PublicKey, any] => {
  const p = new BN(_p, 10)
  const q = new BN(_q, 10)
  let g = new BN(_g, 10)
  const sk = new BN(random.int(1, q - 1), 10)
  const h = g.pow(sk).mod(p)

  const test1 = g.pow(q).mod(p)
  if (!test1.eq(new BN(1, 10))) {
    console.error('g^q mod p != 1', test1.toNumber())
  }

  const test2 = h.pow(q).mod(p)
  if (!test2.eq(new BN(1, 10))) {
    console.error('h^q mod p != 1', test2.toNumber())
  }

  if (h.mod(p).eq(new BN(1, 10))) {
    console.error('h mod p == 1', h.mod(p).toNumber())
  }

  const pk = { p: p, g: g, h: h, q: q }

  return [pk, sk]
}

export const getGs = (p: number): number[] => {
  // source: https://asecuritysite.com/encryption/pickg
  const g: number[] = []
  for (let i = 1; i < p; i++) {
    let exp = 1
    let next = i % p

    while (next !== 1) {
      next = (next * i) % p
      exp += 1
    }

    if (exp === p - 1) {
      g.push(i)
    }
  }

  return g
}

<<<<<<< HEAD
export const encrypt = (message: number, pk: PublicKey, log: boolean = false): Cipher => {
  const msg = newBN(message)

  // generate a random value
  const randomValue = newBN(random.int(1, pk.p - 2))
=======
export const encrypt = (message: any, pk: PublicKey, log: boolean = false): Cipher => {
  const msg = typeof message === 'number' ? new BN(message, 10) : message

  // generate a random value
  const randomValue = new BN(random.int(1, pk.q - 1), 10)
>>>>>>> working disjunctive zkp for proof of encrypted vote
  log && console.log('enc secret   (r)', randomValue)

  // compute c1: generator^randomValue
  let c1 = pk.g.pow(randomValue).mod(pk.p)
  log && console.log('c1\t\t', c1)

  // compute s: h^randomValue whereby
  // h = publicKey => h = g^privateKeyOfReceiver (h is publically available)
  const s = pk.h.pow(randomValue).mod(pk.p)
  log && console.log('s\t\t', s)

  // compute mh: generator^message
  const mh = pk.g.pow(msg).mod(pk.p)
  log && console.log('mh\t\t', mh)

  // compute c2: s*message_homomorphic
  const c2 = s.mul(mh).mod(pk.p)
  log && console.log('c2\t\t', c2)
  log && console.log('------------------------')

  return { a: c1, b: c2, r: randomValue }
}

export const add = (em1: Cipher, em2: Cipher, pk: PublicKey): Cipher => {
  return {
    a: em1.a.mul(em2.a).mod(pk.p),
    b: em1.b.mul(em2.b).mod(pk.p),
    r: null,
  }
}

export const decrypt1 = (cipherText: Cipher, sk: any, pk: PublicKey, log: boolean = false): any => {
  let c1 = cipherText.a
  let c2 = cipherText.b

  // compute s: c1^privateKey
  let s = c1.pow(sk).mod(pk.p)
  log && console.log('s\t\t', s)

  // compute s^-1: the multiplicative inverse of s (probably the most difficult)
  let s_inverse = s.invm(pk.p)
  log && console.log('s^-1\t\t', s_inverse)

  // compute m: c2 * s^-1 | c2 / s
  let m_h = c2.mul(s_inverse).mod(pk.p)
  log && console.log('m_h\t\t', m_h)

  // 4.
  let m = newBN(0)
  while (
    !pk.g
      .pow(m)
      .mod(pk.p)
      .eq(m_h)
  ) {
    m = m.add(newBN(1))
  }

  log && console.log('plaintext d1\t', m)
  log && console.log('------------------------')

  return m
}

export const decrypt2 = (cipherText: Cipher, sk: any, pk: PublicKey, log: boolean = false): any => {
  let c1 = cipherText.a
  let c2 = cipherText.b

  // compute s: c1^privateKey
  let s = c1.pow(sk).mod(pk.p)
  log && console.log('s\t\t', s)

  // compute s^-1: the multiplicative inverse of s (probably the most difficult)
  let s_inverse = s.invm(pk.p)
  log && console.log('s^-1\t\t', s_inverse)

  // alternative computation
  // 1. compute p-2
  const pMinusX = pk.p.sub(newBN(2))
  log && console.log('p - 2\t\t', pMinusX)

  // 2. compute pre-result s^(p-x)
  const sPowPMinusX = s.pow(pMinusX).mod(pk.p)
  log && console.log('s^(p-x)\t\t', sPowPMinusX)

  // 3. compute message - msg = c2*s^(p-x)
  let m_h = c2.mul(sPowPMinusX).mod(pk.p)
  log && console.log('msg_homo\t', m_h)

  let m = newBN(1)
  while (
    !pk.g
      .pow(m)
      .mod(pk.p)
      .eq(m_h)
  ) {
    m = m.add(newBN(1))
  }

  log && console.log('plaintext d2\t', m)
  log && console.log('------------------------')

  return m
}
