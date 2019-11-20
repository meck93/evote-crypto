import { Cipher, Helper, SystemParameters, KeyPair } from './index'
import BN = require('bn.js')

export const generateSystemParameters = (_p: number, _g: number): SystemParameters => {
  const p = Helper.newBN(_p)
  const q = Helper.newBN(Helper.getQofP(_p))
  const g = Helper.newBN(_g)
  return { p, q, g }
}

export const generateKeyPair = (sp: SystemParameters): KeyPair => {
  const sk = Helper.getSecureRandomValue(sp.q)
  const h = Helper.BNpow(sp.g, sk, sp.p)
  return { h, sk }
}

export const generateSystemParametersAndKeys = (
  p: number,
  g: number
): [SystemParameters, KeyPair] => {
  const sysParams = generateSystemParameters(p, g)
  const keyPair = generateKeyPair(sysParams)
  return [sysParams, keyPair]
}

export const generateSystemParametersAndKeysZKP = (
  _p: number,
  _g: number
): [SystemParameters, KeyPair] => {
  const sysParams = generateSystemParameters(_p, _g)
  const keyPair = generateKeyPair(sysParams)

  // verify that g^q mod p == 1 (this means: gcd(q,p) == 1)
  const test1 = Helper.BNpow(sysParams.g, sysParams.q, sysParams.p)
  if (!test1.eq(Helper.newBN(1))) {
    throw new Error(
      `g^q mod p != 1 (== ${test1.toNumber()}. for p: ${_p}, q: ${sysParams.q.toNumber()} and g: ${_g}`
    )
  }

  // verify that h^q mod p == 1 (this means: gcd(h,p) == 1)
  const test2 = Helper.BNpow(keyPair.h, sysParams.q, sysParams.p)
  if (!test2.eq(Helper.newBN(1))) {
    throw new Error(
      `h^q mod p != 1 (== ${test2.toNumber()}. for p: ${_p}, q: ${sysParams.q.toNumber()} and g: ${_g}`
    )
  }

  // verify that the public key h is not 1
  const test3 = keyPair.h.mod(sysParams.p)
  if (test3.eq(Helper.newBN(1))) {
    throw new Error(`h mod p == 1. for p: ${_p}, q: ${sysParams.q.toNumber()} and g: ${_g}`)
  }

  return [sysParams, keyPair]
}

export const encodeMessage = (m: number | BN, sysParams: SystemParameters): BN => {
  m = typeof m === 'number' ? Helper.newBN(m) : m
  return Helper.BNpow(sysParams.g, m, sysParams.p)
}

// TODO: use baby-step giant-step instead of brute force
export const decodeMessage = (mh: number | BN, sysParams: SystemParameters): BN => {
  mh = typeof mh === 'number' ? Helper.newBN(mh) : mh

  let m = Helper.newBN(0)
  while (!encodeMessage(m, sysParams).eq(mh)) {
    m = m.add(Helper.newBN(1))
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
export const encrypt = (
  message: number | BN,
  sysParams: SystemParameters,
  publicKey: BN,
  log = false
): Cipher => {
  const m = typeof message === 'number' ? Helper.newBN(message) : message

  const r = Helper.getSecureRandomValue(sysParams.q)
  const c1 = Helper.BNpow(sysParams.g, r, sysParams.p)
  const s = Helper.BNpow(publicKey, r, sysParams.p)
  const mh = encodeMessage(m, sysParams)
  const c2 = Helper.BNmul(s, mh, sysParams.p)

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
export const decrypt1 = (
  cipherText: Cipher,
  sk: BN,
  sysParams: SystemParameters,
  log = false
): BN => {
  const { a: c1, b: c2 } = cipherText

  const s = Helper.BNpow(c1, sk, sysParams.p)
  const sInverse = Helper.BNinvm(s, sysParams.p)
  const mh = Helper.BNmul(c2, sInverse, sysParams.p)
  const m = decodeMessage(mh, sysParams)

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
export const decrypt2 = (
  cipherText: Cipher,
  sk: BN,
  sysParams: SystemParameters,
  log = false
): BN => {
  const { a: c1, b: c2 } = cipherText

  const s = Helper.BNpow(c1, sk, sysParams.p)
  const sPowPMinus2 = Helper.BNpow(s, sysParams.p.sub(Helper.newBN(2)), sysParams.p)
  const mh = Helper.BNmul(c2, sPowPMinus2, sysParams.p)
  const m = decodeMessage(mh, sysParams)

  log && console.log('s\t\t', s)
  log && console.log('s^(p-2)\t\t', sPowPMinus2)
  log && console.log('mh\t', mh)
  log && console.log('plaintext d2\t', m)
  log && console.log('------------------------')

  return m
}

export const add = (em1: Cipher, em2: Cipher, sysParams: SystemParameters): Cipher => {
  return {
    a: Helper.BNmul(em1.a, em2.a, sysParams.p),
    b: Helper.BNmul(em1.b, em2.b, sysParams.p),
  }
}
