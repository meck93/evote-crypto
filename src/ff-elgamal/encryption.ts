/**
 * Encryption
 *
 * ElGamal Finite Field Encryption
 * - encode and decode messages
 * - encrypt and decrypt messages
 * - homomorphically add encrypted messages
 * - decrypt cipher texts with a private key share
 * - combine decrypted shares
 */

import BN = require('bn.js')
import { GlobalHelper } from '../index'
import { Cipher, Helper, SystemParameters } from './index'

// encode a message m to g^m
export const encodeMessage = (m: number | BN, sysParams: SystemParameters): BN => {
  m = typeof m === 'number' ? GlobalHelper.newBN(m) : m
  return Helper.BNpow(sysParams.g, m, sysParams.p)
}

// decode a message g^m to m
// TODO: use baby-step giant-step instead of brute force
export const decodeMessage = (mh: number | BN, sysParams: SystemParameters): BN => {
  mh = typeof mh === 'number' ? GlobalHelper.newBN(mh) : mh

  let m = GlobalHelper.newBN(0)
  while (!encodeMessage(m, sysParams).eq(mh)) {
    m = m.add(GlobalHelper.newBN(1))
  }
  return m
}

// TODO: test encryption and both decryption for the whole message range
// (to verify the correct implementation and usage of decodeMessage)

// Finite Field ElGamal Encryption
//
// given:
// - p: prime number
// - g: generator
// - h: public key (g^privateKey)
// - m: message
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
  const m = typeof message === 'number' ? GlobalHelper.newBN(message) : message

  const r = GlobalHelper.getSecureRandomValue(sysParams.q)
  const c1 = Helper.BNpow(sysParams.g, r, sysParams.p)
  const s = Helper.BNpow(publicKey, r, sysParams.p)
  const mh = encodeMessage(m, sysParams)
  const c2 = GlobalHelper.mulBN(s, mh, sysParams.p)

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
// - p: prime number
// - g: generator
// - x: private key
// - c1,c2: cipher
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
  const sInverse = GlobalHelper.invmBN(s, sysParams.p)
  const mh = GlobalHelper.mulBN(c2, sInverse, sysParams.p)
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
// - p: prime number
// - g: generator
// - x: private key
// - c1,c2: cipher
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
  const sPowPMinus2 = Helper.BNpow(s, sysParams.p.sub(GlobalHelper.newBN(2)), sysParams.p)
  const mh = GlobalHelper.mulBN(c2, sPowPMinus2, sysParams.p)
  const m = decodeMessage(mh, sysParams)

  log && console.log('s\t\t', s)
  log && console.log('s^(p-2)\t\t', sPowPMinus2)
  log && console.log('mh\t', mh)
  log && console.log('plaintext d2\t', m)
  log && console.log('------------------------')

  return m
}

// homomorphic addition
export const add = (em1: Cipher, em2: Cipher, sysParams: SystemParameters): Cipher => {
  return {
    a: GlobalHelper.mulBN(em1.a, em2.a, sysParams.p),
    b: GlobalHelper.mulBN(em1.b, em2.b, sysParams.p),
  }
}

// decrypt a cipher text with a private key share
export const decryptShare = (params: SystemParameters, cipher: Cipher, secretKeyShare: BN): BN => {
  return Helper.BNpow(cipher.a, secretKeyShare, params.p)
}

// combine decrypted shares
export const combineDecryptedShares = (
  params: SystemParameters,
  cipher: Cipher,
  decryptedShares: BN[]
): BN => {
  const mh = GlobalHelper.divBN(
    cipher.b,
    decryptedShares.reduce((product, share) => GlobalHelper.mulBN(product, share, params.p)),
    params.p
  )

  return decodeMessage(mh, params)
}
