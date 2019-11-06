import { Cipher } from '../models'
import { getSecureRandomValue } from './helper'

const BN = require('bn.js')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')

const shouldLog = false

// Elliptic Curve ElGamal Encryption
//
// given:
// - g: generator
// - h: public key (g^privateKey)
// - m: message
//
// steps:
// 1. pick random value r
// 2. compute c1 = g^r (ec-multiplication)
// 3. compute s = h^r (ec-multiplication)
// 4. compute c2 = s*m
export const encrypt = (message: any, pubK: any): Cipher => {
  const r = getSecureRandomValue()

  const c1 = ec.g.mul(r)
  const s = pubK.mul(r)
  const c2 = s.add(message)

  shouldLog && console.log('Is c1 on the curve?', ec.curve.validate(c1))
  shouldLog && console.log('Is point s on the curve?', ec.curve.validate(s))
  shouldLog && console.log('is c2 on curve?', ec.curve.validate(c2))

  return { a: c1, b: c2, r: r }
}

// Elliptic Curve ElGamal Decryption
//
// given:
// - g: generator
// - x: private key
// - c1,c2: cipher
//
// steps:
// 1. compute s = c1^x (ec-multiplication)
// 2. compute s^-1 = multiplicative inverse of s
// 3. compute m = c2 * s^-1 (ec-addition)
export const decrypt = (cipherText: Cipher, privK: any): any => {
  const { a: c1, b: c2 } = cipherText

  const s = c1.mul(privK)
  const sInverse = s.neg()
  const m = c2.add(sInverse)

  shouldLog && console.log('is s on the curve?', ec.curve.validate(s))
  shouldLog && console.log('is s^-1 on the curve?', ec.curve.validate(sInverse))
  shouldLog && console.log('is m on curve?', ec.curve.validate(m))

  return m
}

export const homomorphicAdd = (cipher0: Cipher, cipher1: Cipher): Cipher => {
  return {
    a: cipher0.a.add(cipher1.a),
    b: cipher0.b.add(cipher1.b),
  }
}
