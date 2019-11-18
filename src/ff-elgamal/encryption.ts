import { PublicKey } from './models'
import { Cipher } from '../models'
import { getQofP, getSecureRandomValue, newBN, BNmul, BNpow, BNinvm } from './helper'

import BN = require('bn.js')

export const generateKeys = (_p: number, _g: number): [PublicKey, any] => {
  const p = newBN(_p)
  const q = newBN(getQofP(_p))
  const g = newBN(_g)

  const sk = getSecureRandomValue(q)
  const h = BNpow(g, sk, p)

  const pk = { p, g, h, q }

  return [pk, sk]
}

export const generateKeysZKP = (_p: number, _g: number): [PublicKey, any] => {
  const p = newBN(_p)
  const q = newBN(getQofP(_p))
  const g = newBN(_g)

  const sk = getSecureRandomValue(q)
  const h = BNpow(g, sk, p)

  const pk = { p, g, h, q }

  // verify that g^q mod p == 1 (this means: gcd(q,p) == 1)
  const test1 = BNpow(g, q, pk.p)
  if (!test1.eq(newBN(1))) {
    throw new Error(`g^q mod p != 1 (== ${test1.toNumber()}. for p: ${_p}, q: ${q.toNumber()} and g: ${_g}`)
  }

  // verify that h^q mod p == 1 (this means: gcd(h,p) == 1)
  const test2 = BNpow(h, q, pk.p)
  if (!test2.eq(newBN(1))) {
    throw new Error(`h^q mod p != 1 (== ${test2.toNumber()}. for p: ${_p}, q: ${q.toNumber()} and g: ${_g}`)
  }

  // verify that the public key h is not 1
  const test3 = h.mod(pk.p)
  if (test3.eq(newBN(1))) {
    throw new Error(`h mod p == 1. for p: ${_p}, q: ${q.toNumber()} and g: ${_g}`)
  }

  return [pk, sk]
}

export const encodeMessage = (m: any, pk: PublicKey) => {
  m = typeof m === 'number' ? newBN(m) : m
  return BNpow(pk.g, m, pk.p)
}

// TODO: use baby-step giant-step instead of brute force
export const decodeMessage = (mh: any, pk: PublicKey) => {
  mh = typeof mh === 'number' ? newBN(mh) : mh

  let m = newBN(0)
  while (!encodeMessage(m, pk).eq(mh)) {
    m = m.add(newBN(1))
  }
  return m
}

// TODO: test encryption and both decryption for the whole message range
// (to verify the correct implementation and usage of decodeMessage)

// Finite Field ElGamal Encryption
//
// given:
// - g: generator
// - h: public key (g^privateKey)
// - m: message
// (- p: prime number)
//
// steps:
// 1. pick random value r: 0 < r < p
// 2. compute c1 = g^r
// 3. compute s = h^r
// 4. compute mh = g^message (encode it to make it "homomorphic")
// 5. compute c2 = s*mh
export const encrypt = (message: any, pk: PublicKey, log: boolean = false): Cipher => {
  const m = typeof message === 'number' ? newBN(message) : message

  const r = getSecureRandomValue(pk.q)
  const c1 = BNpow(pk.g, r, pk.p)
  const s = BNpow(pk.h, r, pk.p)
  const mh = encodeMessage(m, pk)
  const c2 = BNmul(s, mh, pk.p)

  log && console.log('enc secret   (r)', r)
  log && console.log('a\t\t', c1)
  log && console.log('h^r\t\t', s)
  log && console.log('g^m\t\t', mh)
  log && console.log('b\t\t', c2)
  log && console.log('------------------------')

  return { a: c1, b: c2, r }
}

// Finite Field ElGamal Decryption
//
// given:
// - g: generator
// - x: private key
// - c1,c2: cipher
// (- p: prime number)
//
// steps:
// 1. compute s = c1^x
// 2. compute s^-1 = multiplicative inverse of s
// 3. compute mh = c2 * s^-1
// 4. compute m (decode mh using brute force)
export const decrypt1 = (cipherText: Cipher, sk: any, pk: PublicKey, log: boolean = false): any => {
  const { a: c1, b: c2 } = cipherText

  const s = BNpow(c1, sk, pk.p)
  const sInverse = BNinvm(s, pk.p)
  const mh = BNmul(c2, sInverse, pk.p)
  const m = decodeMessage(mh, pk)

  log && console.log('s\t\t', s)
  log && console.log('s^-1\t\t', sInverse)
  log && console.log('mh\t\t', mh)
  log && console.log('plaintext d1\t', m)
  log && console.log('------------------------')

  return m
}

// Finite Field ElGamal Decryption Alternative (using Euler's Theorem)
//
// given:
// - g: generator
// - x: private key
// - c1,c2: cipher
// (- p: prime number)
//
// steps:
// 1. compute s = c1^x
// 2. compute s^-1 = multiplicative inverse of s
// 3. compute s^(p-2)
// 4. compute mh = c2 * s^(p-2)
// 5. compute m (decode mh using brute force)
export const decrypt2 = (cipherText: Cipher, sk: any, pk: PublicKey, log: boolean = false): any => {
  const { a: c1, b: c2 } = cipherText

  const s = BNpow(c1, sk, pk.p)
  const sPowPMinus2 = BNpow(s, pk.p.sub(newBN(2)), pk.p)
  const mh = BNmul(c2, sPowPMinus2, pk.p)
  const m = decodeMessage(mh, pk)

  log && console.log('s\t\t', s)
  log && console.log('s^(p-2)\t\t', sPowPMinus2)
  log && console.log('mh\t', mh)
  log && console.log('plaintext d2\t', m)
  log && console.log('------------------------')

  return m
}

export const add = (em1: Cipher, em2: Cipher, pk: PublicKey): Cipher => {
  return {
    a: BNmul(em1.a, em2.a, pk.p),
    b: BNmul(em1.b, em2.b, pk.p),
  }
}
