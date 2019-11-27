import BN = require('bn.js')
import { Cipher, CurvePoint, Helper, Curve } from './index'

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
export const encrypt = (message: CurvePoint, publicKey: CurvePoint, log = false): Cipher => {
  const r = Helper.getSecureRandomValue(Curve.n)

  const c1 = Curve.g.mul(r) as CurvePoint
  const s = publicKey.mul(r)
  const c2 = s.add(message) as CurvePoint

  log && console.log('Is c1 on the curve?\t', Curve.validate(c1))
  log && console.log('Is point s on the curve?', Curve.validate(s))
  log && console.log('Is c2 on curve?\t\t', Curve.validate(c2))

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
export const decrypt = (cipherText: Cipher, privateKey: BN, log = false): CurvePoint => {
  const { a: c1, b: c2 } = cipherText

  const s = c1.mul(privateKey)
  const sInverse = s.neg()
  const m = c2.add(sInverse)

  log && console.log('is s on the curve?', Curve.validate(s))
  log && console.log('is s^-1 on the curve?', Curve.validate(sInverse))
  log && console.log('is m on curve?', Curve.validate(m))

  return m as CurvePoint
}

export const homomorphicAdd = (cipher0: Cipher, cipher1: Cipher): Cipher => {
  return {
    a: cipher0.a.add(cipher1.a) as CurvePoint,
    b: cipher0.b.add(cipher1.b) as CurvePoint,
  }
}

// decrypt a cipher text with a private key share
export const decryptShare = (cipher: Cipher, secretKeyShare: BN): CurvePoint => {
  return Helper.ECpow(cipher.a, secretKeyShare)
}

// combine decrypted shares
export const combineDecryptedShares = (
  cipher: Cipher,
  decryptedShares: CurvePoint[]
): CurvePoint => {
  const mh = Helper.ECdiv(
    cipher.b,
    decryptedShares.reduce((product, share) => Helper.ECmul(product, share))
  )
  return mh
}
