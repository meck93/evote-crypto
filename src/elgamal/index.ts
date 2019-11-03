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

export const newBN = (n: number) => new BN(n, 10)

// modulo operations
const mul = (a: any, b: any, pk: PublicKey) => a.mul(b).mod(pk.p)
const pow = (a: any, b: any, pk: PublicKey) => a.pow(b).mod(pk.p)
const invm = (a: any, pk: PublicKey) => a.invm(pk.p)

// calculate q given p
export const getQofP = (p: any) => (p - 1) / 2

export const generateKeys = (_p: number, _g: number): [PublicKey, any] => {
  const p = newBN(_p)
  const q = newBN(getQofP(_p))
  const g = newBN(_g)
  const sk = newBN(random.int(1, q - 1))
  const h = g.pow(sk).mod(p)

  const pk = { p, g, h, q }

  const test1 = pow(g, q, pk)
  if (!test1.eq(newBN(1))) {
    console.error('g^q mod p != 1', test1.toNumber())
  }

  const test2 = pow(h, q, pk)
  if (!test2.eq(newBN(1))) {
    console.error('h^q mod p != 1', test2.toNumber())
  }

  if (h.mod(pk.p).eq(newBN(1))) {
    console.error('h mod p == 1', h.mod(pk.p).toNumber())
  }

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

export const encrypt = (message: any, pk: PublicKey, log: boolean = false): Cipher => {
  const msg = typeof message === 'number' ? newBN(message) : message

  // generate a random value
  const randomValue = newBN(random.int(1, pk.q - 1))
  
  // compute c1: generator^randomValue
  let c1 = pow(pk.g, randomValue, pk)
  
  // compute s: h^randomValue whereby
  // h = publicKey => h = g^privateKeyOfReceiver (h is publically available)
  const s = pow(pk.h, randomValue, pk)
  
  // compute mh: generator^message
  const mh = pow(pk.g, msg, pk)
  
  // compute c2: s*message_homomorphic
  const c2 = mul(s, mh, pk)
  
  log && console.log('enc secret   (r)', randomValue)
  log && console.log('c1\t\t', c1)
  log && console.log('s\t\t', s)
  log && console.log('mh\t\t', mh)
  log && console.log('c2\t\t', c2)
  log && console.log('------------------------')

  return { a: c1, b: c2, r: randomValue }
}

export const add = (em1: Cipher, em2: Cipher, pk: PublicKey): Cipher => {
  return {
    a: mul(em1.a, em2.a, pk),
    b: mul(em1.b, em2.b, pk),
    r: null,
  }
}

export const decrypt1 = (cipherText: Cipher, sk: any, pk: PublicKey, log: boolean = false): any => {
  let c1 = cipherText.a
  let c2 = cipherText.b

  // compute s: c1^privateKey
  let s = pow(c1, sk, pk)
  
  // compute s^-1: the multiplicative inverse of s (probably the most difficult)
  let s_inverse = invm(s, pk)
  
  // compute m: c2 * s^-1 | c2 / s
  let m_h = mul(c2, s_inverse, pk)
  
  // 4.
  let m = newBN(0)
  while (!pow(pk.g, m, pk).eq(m_h)) {
    m = m.add(newBN(1))
  }
  
  log && console.log('s\t\t', s)
  log && console.log('s^-1\t\t', s_inverse)
  log && console.log('m_h\t\t', m_h)
  log && console.log('plaintext d1\t', m)
  log && console.log('------------------------')

  return m
}

export const decrypt2 = (cipherText: Cipher, sk: any, pk: PublicKey, log: boolean = false): any => {
  let c1 = cipherText.a
  let c2 = cipherText.b

  // compute s: c1^privateKey
  let s = pow(c1, sk, pk)
  
  // compute s^-1: the multiplicative inverse of s (probably the most difficult)
  let s_inverse = invm(s, pk)
  
  // alternative computation
  // 1. compute p-2
  const pMinusX = pk.p.sub(newBN(2))
  
  // 2. compute pre-result s^(p-x)
  const sPowPMinusX = pow(s, pMinusX, pk)
  
  // 3. compute message - msg = c2*s^(p-x)
  let m_h = mul(c2, sPowPMinusX, pk)
  
  let m = newBN(1)
  while (!pow(pk.g, m, pk).eq(m_h)) {
    m = m.add(newBN(1))
  }
  
  log && console.log('s\t\t', s)
  log && console.log('s^-1\t\t', s_inverse)
  log && console.log('p - 2\t\t', pMinusX)
  log && console.log('s^(p-x)\t\t', sPowPMinusX)
  log && console.log('msg_homo\t', m_h)
  log && console.log('plaintext d2\t', m)
  log && console.log('------------------------')

  return m
}
