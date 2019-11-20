import { ECelGamal } from '..'
import { ECpow, ECdiv, ECmul, BNmul, BNadd, curvePointsToString } from './helper'
import BN = require('bn.js')
import { ec as EC } from 'elliptic'

import { activeCurve } from './activeCurve'
import { CurvePoint, KeyShareProof, Cipher } from './models'
const web3 = require('web3')

export const generateSystemParameters = (): ECelGamal.SystemParameters => {
  return { p: activeCurve.curve.p, n: activeCurve.curve.n, g: activeCurve.curve.g }
}

export const generateKeyPair = (): EC.KeyPair => {
  return activeCurve.genKeyPair()
}

export const generateKeyShares = (): ECelGamal.KeyShare => {
  // generate first key pair (sk, h)
  const keyPair: EC.KeyPair = generateKeyPair()
  const sk: BN = keyPair.getPrivate()
  const h: CurvePoint = keyPair.getPublic() as CurvePoint

  return { h_: h, sk_: sk }
}

export const generateKeyPairs = (n: number): EC.KeyPair[] => {
  const res: EC.KeyPair[] = []
  for (let i = 0; i < n; i++) {
    res.push(generateKeyPair())
  }
  return res
}

export const generateChallenge = (n: BN, uniqueID: string, h_: CurvePoint, b: CurvePoint): BN => {
  const pointsAsString = curvePointsToString([h_, b])
  const hashString: string = web3.utils.soliditySha3(uniqueID, pointsAsString)
  let c: BN = web3.utils.toBN(hashString)
  c = c.mod(n)
  return c
}

export const generateKeyGenerationProof = (params: ECelGamal.SystemParameters, share: ECelGamal.KeyShare, id: string): KeyShareProof => {
  const { n } = params
  const { h_, sk_ } = share

  // generate a second key pair (a,b)
  const keyPair: EC.KeyPair = activeCurve.genKeyPair()
  const a: BN = keyPair.getPrivate()
  const b: CurvePoint = keyPair.getPublic() as CurvePoint

  // compute challenge hash(h_, b)
  const c: BN = generateChallenge(n, id, h_, b)

  // compute d = a + c*sk_
  const d: BN = BNadd(a, BNmul(c, sk_, n), n)

  return { c: c, d: d }
}

export const verifyKeyGenerationProof = (params: ECelGamal.SystemParameters, proof: KeyShareProof, h_: CurvePoint, id: string): boolean => {
  const { n, g } = params
  const { c, d } = proof

  // recompute b = g^d/h_^c
  // const b: BN = BNdiv(BNpow(g, d, p), BNpow(h_, c, p), p)
  const b: CurvePoint = ECdiv(ECpow(g, d), ECpow(h_, c))

  // recompute the challenge c = hash(id, h_, b)
  const c_: BN = generateChallenge(n, id, h_, b)
  const hashCheck: boolean = c.eq(c_)

  // verify that: g^d == b * h_^c
  const gPowd: CurvePoint = ECpow(g, d)
  const bhPowC: CurvePoint = ECmul(b, ECpow(h_, c))
  const dCheck: boolean = gPowd.eq(bhPowC)

  console.log('do the hashes match?\t', hashCheck)
  console.log('g^d == b * h_^c?\t', dCheck)
  console.log()

  return hashCheck && dCheck
}

export const combinePublicKeys = (publicKeyShares: CurvePoint[]): CurvePoint => {
  return publicKeyShares.reduce((product, share) => ECmul(product, share))
}

// NOTE: this should not be used as the distributed secret keys will become "useless"
// it is only used for testing purpose
export const combinePrivateKeys = (params: ECelGamal.SystemParameters, privateKeyShares: BN[]): BN => {
  return privateKeyShares.reduce((sum, share) => BNadd(sum, share, params.n))
}

export const decryptShare = (cipher: Cipher, secretKeyShare: BN): CurvePoint => {
  return ECpow(cipher.a, secretKeyShare)
}

export const combineDecryptedShares = (cipher: Cipher, decryptedShares: CurvePoint[]): CurvePoint => {
  const mh = ECdiv(
    cipher.b,
    decryptedShares.reduce((product, share) => ECmul(product, share))
  )
  return mh
}
