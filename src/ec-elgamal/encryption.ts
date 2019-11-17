import { getSecureRandomValue } from './helper'
import { ECCipher } from './models'
import { curve } from 'elliptic'

import BN = require('bn.js')
const EC = require('elliptic').ec
const curve25519 = new EC('curve25519-weier')

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
export const encrypt = (message: curve.base.BasePoint, pubK: curve.base.BasePoint): ECCipher => {
  const r = getSecureRandomValue()

  const c1 = curve25519.g.mul(r)
  const s = pubK.mul(r)
  const c2 = s.add(message)

  shouldLog && console.log('Is c1 on the curve?\t', curve25519.curve.validate(c1))
  shouldLog && console.log('Is point s on the curve?', curve25519.curve.validate(s))
  shouldLog && console.log('Is c2 on curve?\t\t', curve25519.curve.validate(c2))

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
export const decrypt = (cipherText: ECCipher, privK: BN): any => {
  const { a: c1, b: c2 } = cipherText

  const s = c1.mul(privK)
  const sInverse = s.neg()
  const m = c2.add(sInverse)

  shouldLog && console.log('is s on the curve?', curve25519.curve.validate(s))
  shouldLog && console.log('is s^-1 on the curve?', curve25519.curve.validate(sInverse))
  shouldLog && console.log('is m on curve?', curve25519.curve.validate(m))

  return m
}

export const homomorphicAdd = (cipher0: ECCipher, cipher1: ECCipher): ECCipher => {
  return {
    a: cipher0.a.add(cipher1.a),
    b: cipher0.b.add(cipher1.b),
  }
}
