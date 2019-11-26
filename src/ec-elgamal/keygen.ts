import { ECelGamal } from '..'
import { ECpow, ECdiv, ECmul, BNmul, BNadd, curvePointsToString } from './helper'
import BN = require('bn.js')
import { ec as EC } from 'elliptic'

import { activeCurve } from './activeCurve'
import { CurvePoint, KeyShareProof, Cipher } from './models'
const web3 = require('web3')

export const generateChallenge = (n: BN, uniqueID: string, h_: CurvePoint, b: CurvePoint): BN => {
  const pointsAsString = curvePointsToString([h_, b])
  const hashString: string = web3.utils.soliditySha3(uniqueID, pointsAsString)
  let c: BN = web3.utils.toBN(hashString)
  c = c.mod(n)
  return c
}

export const generateKeyGenerationProof = (
  params: ECelGamal.SystemParameters,
  share: ECelGamal.KeyPair,
  id: string
): KeyShareProof => {
  const { n } = params
  const { h, sk } = share

  // generate a second key pair (a,b)
  const keyPair: EC.KeyPair = activeCurve.genKeyPair()
  const a: BN = keyPair.getPrivate()
  const b: CurvePoint = keyPair.getPublic() as CurvePoint

  // compute challenge hash(h_, b)
  const c: BN = generateChallenge(n, id, h, b)

  // compute d = a + c*sk_
  const d: BN = BNadd(a, BNmul(c, sk, n), n)

  return { c: c, d: d }
}

export const verifyKeyGenerationProof = (
  params: ECelGamal.SystemParameters,
  proof: KeyShareProof,
  h_: CurvePoint,
  id: string
): boolean => {
  const log = false
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

  log && console.log('do the hashes match?\t', hashCheck)
  log && console.log('g^d == b * h_^c?\t', dCheck)
  log && console.log()

  return hashCheck && dCheck
}
